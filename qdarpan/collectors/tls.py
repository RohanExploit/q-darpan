"""Live TLS discovery.

This is the only collector that opens a socket, and it is the only one whose
findings are observations rather than inferences. A negotiated cipher suite is
not a guess about what the code might do -- it is what the server actually did,
which is why NEGOTIATED sits at the top of the confidence ladder.

It is skipped entirely under ``--offline``. Concurrency and timeouts are bounded
so that walking 2,300 endpoints does not resemble a port scan.
"""

from __future__ import annotations

import re
import socket
import ssl
from datetime import timezone
from typing import Iterator, List, Optional, Tuple

from ..canonical import Registry, UnknownAlgorithm, default_registry
from ..ir import (
    TIER_CONFIDENCE,
    AssetKind,
    CryptoFinding,
    CryptoFunction,
    Evidence,
    EvidenceTier,
    Location,
    Primitive,
    Surface,
)
from .base import Collector, Result, Target, TargetKind

DEFAULT_TIMEOUT = 6.0

#: Curves offered when probing which groups a server will accept. Each name is
#: an OpenSSL curve name accepted by ``SSLContext.set_ecdh_curve``.
PROBE_CURVES = ("prime256v1", "secp384r1", "secp521r1", "X25519")

_PROTOCOL_VERSIONS = {
    "TLSv1": ssl.TLSVersion.TLSv1,
    "TLSv1.1": ssl.TLSVersion.TLSv1_1,
    "TLSv1.2": ssl.TLSVersion.TLSv1_2,
    "TLSv1.3": ssl.TLSVersion.TLSv1_3,
}

#: Cipher-suite name fragments mapped onto registry algorithms. Both the
#: OpenSSL spelling (ECDHE-RSA-AES256-GCM-SHA384) and the IANA spelling
#: (TLS_AES_256_GCM_SHA384) decompose through this table.
_SUITE_TOKENS = (
    ("ECDHE", "ECDH", {}, Primitive.KEY_AGREE, ["keyderive"]),
    ("ECDH", "ECDH", {}, Primitive.KEY_AGREE, ["keyderive"]),
    ("DHE", "DH", {}, Primitive.KEY_AGREE, ["keyderive"]),
    ("AES_256_GCM", "AES", {"key_size": 256, "mode": "gcm"}, Primitive.AE, ["encrypt"]),
    ("AES_128_GCM", "AES", {"key_size": 128, "mode": "gcm"}, Primitive.AE, ["encrypt"]),
    ("AES256-GCM", "AES", {"key_size": 256, "mode": "gcm"}, Primitive.AE, ["encrypt"]),
    ("AES128-GCM", "AES", {"key_size": 128, "mode": "gcm"}, Primitive.AE, ["encrypt"]),
    ("AES_256_CBC", "AES", {"key_size": 256, "mode": "cbc"}, Primitive.BLOCK_CIPHER, ["encrypt"]),
    ("AES_128_CBC", "AES", {"key_size": 128, "mode": "cbc"}, Primitive.BLOCK_CIPHER, ["encrypt"]),
    ("AES256-SHA", "AES", {"key_size": 256, "mode": "cbc"}, Primitive.BLOCK_CIPHER, ["encrypt"]),
    ("AES128-SHA", "AES", {"key_size": 128, "mode": "cbc"}, Primitive.BLOCK_CIPHER, ["encrypt"]),
    ("CHACHA20", "ChaCha20", {}, Primitive.STREAM_CIPHER, ["encrypt"]),
    ("3DES", "3DES", {}, Primitive.BLOCK_CIPHER, ["encrypt"]),
    ("DES-CBC3", "3DES", {}, Primitive.BLOCK_CIPHER, ["encrypt"]),
    ("RC4", "RC4", {}, Primitive.STREAM_CIPHER, ["encrypt"]),
    ("SHA384", "SHA-2", {"key_size": 384}, Primitive.HASH, ["digest"]),
    ("SHA256", "SHA-2", {"key_size": 256}, Primitive.HASH, ["digest"]),
    ("_SHA", "SHA-1", {}, Primitive.HASH, ["digest"]),
)

_KEY_ALGORITHMS = {
    "rsa": "RSA",
    "ec": "ECDSA",
    "ed25519": "EdDSA",
    "ed448": "EdDSA",
    "dsa": "DSA",
}


class TLSCollector(Collector):
    """Performs a TLS handshake and reports what was actually negotiated."""

    name = "tls"
    surface = Surface.TLS

    def __init__(
        self,
        registry: Optional[Registry] = None,
        timeout: float = DEFAULT_TIMEOUT,
        probe_groups: bool = False,
        probe_versions: bool = False,
    ):
        self.registry = registry or default_registry()
        self.timeout = timeout
        self.probe_groups = probe_groups
        self.probe_versions = probe_versions

    def supports(self, target: Target) -> bool:
        return target.kind == TargetKind.ENDPOINT

    def collect(self, target: Target) -> Iterator[Result]:
        endpoint = target.endpoint
        if endpoint is None:
            return

        try:
            version, cipher, der = self._handshake(target.host, target.port)
        except (OSError, ssl.SSLError) as exc:
            yield self.error(target, "handshake", "%s: %s" % (type(exc).__name__, exc), endpoint)
            return

        yield self._protocol_finding(target, version, cipher)
        for finding in self._suite_findings(target, cipher):
            yield finding
        if der:
            for finding in self._certificate_findings(target, der):
                yield finding

        if self.probe_versions:
            for finding in self._version_probe(target):
                yield finding
        if self.probe_groups:
            for finding in self._group_probe(target):
                yield finding

    # -- handshake --------------------------------------------------------

    def _context(self) -> ssl.SSLContext:
        """A context that connects to anything and validates nothing.

        Certificate validation is deliberately off: the job is to inventory
        what an endpoint presents, including expired and self-signed
        certificates, which are exactly the ones an operator most needs to see.
        """
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        try:
            context.set_ciphers("ALL:@SECLEVEL=0")
        except ssl.SSLError:
            pass
        return context

    def _handshake(
        self, host: str, port: int, context: Optional[ssl.SSLContext] = None
    ) -> Tuple[Optional[str], Optional[Tuple], Optional[bytes]]:
        context = context or self._context()
        with socket.create_connection((host, port), timeout=self.timeout) as raw:
            with context.wrap_socket(raw, server_hostname=host) as tls:
                return tls.version(), tls.cipher(), tls.getpeercert(binary_form=True)

    # -- protocol ---------------------------------------------------------

    def _protocol_finding(self, target: Target, version: Optional[str], cipher) -> CryptoFinding:
        version_number = (version or "").replace("TLSv", "") or "unknown"
        suite = cipher[0] if cipher else None
        return CryptoFinding(
            target_id=target.target_id,
            asset_kind=AssetKind.PROTOCOL,
            name="TLS%s" % version_number,
            location=Location(surface=self.surface, endpoint=target.endpoint),
            evidence=(
                Evidence(
                    tier=EvidenceTier.NEGOTIATED,
                    matcher_id="tls.handshake",
                    snippet="%s %s" % (version, suite),
                    detail={"cipher_suite": suite},
                ),
            ),
            collector=self.name,
            primitive=Primitive.OTHER,
            parameters={"version": version_number, "protocol": "TLS", "cipher_suite": suite},
        ).with_confidence(TIER_CONFIDENCE[EvidenceTier.NEGOTIATED])

    # -- cipher suite decomposition ----------------------------------------

    def _suite_findings(self, target: Target, cipher) -> Iterator[CryptoFinding]:
        """Break a negotiated suite into its constituent algorithms.

        Longest token first, so ``AES_256_GCM`` is consumed before a bare
        ``AES`` would be and ``SHA384`` before ``_SHA``.
        """
        if not cipher:
            return
        suite = str(cipher[0]).upper()
        consumed = suite
        for token, algorithm, parameters, primitive, functions in _SUITE_TOKENS:
            if token not in consumed:
                continue
            consumed = consumed.replace(token, "", 1)
            try:
                canonical = self.registry.canonicalise(algorithm, dict(parameters))
            except UnknownAlgorithm:
                continue
            yield CryptoFinding(
                target_id=target.target_id,
                asset_kind=AssetKind.ALGORITHM,
                name=canonical.name,
                location=Location(surface=self.surface, endpoint=target.endpoint),
                evidence=(
                    Evidence(
                        tier=EvidenceTier.NEGOTIATED,
                        matcher_id="tls.suite.%s" % token.strip("_").lower(),
                        snippet=suite,
                    ),
                ),
                collector=self.name,
                primitive=primitive,
                parameters=canonical.parameters,
                oid=canonical.oid,
                functions=frozenset(CryptoFunction(f) for f in functions),
            ).with_confidence(TIER_CONFIDENCE[EvidenceTier.NEGOTIATED])

    # -- certificate ------------------------------------------------------

    def _certificate_findings(self, target: Target, der: bytes) -> Iterator[CryptoFinding]:
        try:
            from cryptography import x509
            from cryptography.hazmat.primitives.asymmetric import ec, ed448, ed25519, rsa
        except ImportError:
            return

        try:
            certificate = x509.load_der_x509_certificate(der)
        except Exception:  # noqa: BLE001 - malformed certificates are real
            return

        public_key = certificate.public_key()
        algorithm, parameters = self._describe_key(public_key)

        not_before = getattr(certificate, "not_valid_before_utc", None) or certificate.not_valid_before
        not_after = getattr(certificate, "not_valid_after_utc", None) or certificate.not_valid_after

        subject = certificate.subject.rfc4514_string()
        issuer = certificate.issuer.rfc4514_string()

        yield CryptoFinding(
            target_id=target.target_id,
            asset_kind=AssetKind.CERTIFICATE,
            name="certificate:%s" % subject,
            location=Location(surface=self.surface, endpoint=target.endpoint),
            evidence=(
                Evidence(
                    tier=EvidenceTier.NEGOTIATED,
                    matcher_id="tls.certificate",
                    snippet=subject[:160],
                    detail={
                        "issuer": issuer,
                        "not_before": _iso(not_before),
                        "not_after": _iso(not_after),
                        "serial": format(certificate.serial_number, "x"),
                    },
                ),
            ),
            collector=self.name,
            primitive=Primitive.SIGNATURE,
            parameters={
                "subject": subject,
                "issuer": issuer,
                "not_before": _iso(not_before),
                "not_after": _iso(not_after),
                "signature_algorithm": _signature_algorithm(certificate),
            },
        ).with_confidence(TIER_CONFIDENCE[EvidenceTier.NEGOTIATED])

        if algorithm is None:
            return

        try:
            canonical = self.registry.canonicalise(algorithm, parameters)
        except UnknownAlgorithm:
            return

        yield CryptoFinding(
            target_id=target.target_id,
            asset_kind=AssetKind.ALGORITHM,
            name=canonical.name,
            location=Location(surface=self.surface, endpoint=target.endpoint),
            evidence=(
                Evidence(
                    tier=EvidenceTier.NEGOTIATED,
                    matcher_id="tls.certificate.publickey",
                    snippet="%s in leaf certificate" % canonical.name,
                ),
            ),
            collector=self.name,
            primitive=canonical.primitive,
            parameters=canonical.parameters,
            oid=canonical.oid,
            functions=frozenset({CryptoFunction.SIGN, CryptoFunction.VERIFY}),
        ).with_confidence(TIER_CONFIDENCE[EvidenceTier.NEGOTIATED])

    @staticmethod
    def _describe_key(public_key) -> Tuple[Optional[str], dict]:
        from cryptography.hazmat.primitives.asymmetric import ec, ed448, ed25519, rsa

        if isinstance(public_key, rsa.RSAPublicKey):
            return "RSA", {"key_size": public_key.key_size}
        if isinstance(public_key, ec.EllipticCurvePublicKey):
            return "ECDSA", {"curve": public_key.curve.name}
        if isinstance(public_key, ed25519.Ed25519PublicKey):
            return "EdDSA", {"curve": "Ed25519"}
        if isinstance(public_key, ed448.Ed448PublicKey):
            return "EdDSA", {"curve": "Ed448"}
        return None, {}

    # -- capability probes -------------------------------------------------

    def _version_probe(self, target: Target) -> Iterator[Result]:
        """Find every protocol version the endpoint will accept.

        One connection per version. Costly, so it is opt-in -- but "this host
        still accepts TLS 1.0" is a finding no single handshake reveals.
        """
        for label, version in _PROTOCOL_VERSIONS.items():
            context = self._context()
            try:
                context.minimum_version = version
                context.maximum_version = version
            except ValueError:
                continue
            try:
                self._handshake(target.host, target.port, context)
            except (OSError, ssl.SSLError):
                continue
            yield CryptoFinding(
                target_id=target.target_id,
                asset_kind=AssetKind.PROTOCOL,
                name="TLS%s" % label.replace("TLSv", ""),
                location=Location(surface=self.surface, endpoint=target.endpoint),
                evidence=(
                    Evidence(
                        tier=EvidenceTier.NEGOTIATED,
                        matcher_id="tls.version_probe",
                        snippet="%s accepted" % label,
                    ),
                ),
                collector=self.name,
                primitive=Primitive.OTHER,
                parameters={"version": label.replace("TLSv", ""), "protocol": "TLS"},
            ).with_confidence(TIER_CONFIDENCE[EvidenceTier.NEGOTIATED])

    def _group_probe(self, target: Target) -> Iterator[Result]:
        """Find which key-agreement groups the endpoint will accept.

        Python's ``ssl`` module cannot report the negotiated group before 3.13,
        so this offers one curve at a time and records the ones that complete a
        handshake. Slower than reading it off the wire, but it works on the
        interpreter that is actually installed.
        """
        for curve in PROBE_CURVES:
            context = self._context()
            try:
                context.set_ecdh_curve(curve)
            except (ValueError, ssl.SSLError):
                continue
            try:
                self._handshake(target.host, target.port, context)
            except (OSError, ssl.SSLError):
                continue
            normalised = self.registry.normalise_curve(curve)
            yield CryptoFinding(
                target_id=target.target_id,
                asset_kind=AssetKind.ALGORITHM,
                name="ECDH-%s" % normalised,
                location=Location(surface=self.surface, endpoint=target.endpoint),
                evidence=(
                    Evidence(
                        tier=EvidenceTier.NEGOTIATED,
                        matcher_id="tls.group_probe",
                        snippet="%s accepted" % curve,
                    ),
                ),
                collector=self.name,
                primitive=Primitive.KEY_AGREE,
                parameters={"curve": normalised},
                functions=frozenset({CryptoFunction.KEYDERIVE}),
            ).with_confidence(TIER_CONFIDENCE[EvidenceTier.NEGOTIATED])


def _iso(value) -> Optional[str]:
    if value is None:
        return None
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.isoformat()


def _signature_algorithm(certificate) -> Optional[str]:
    name = getattr(certificate.signature_algorithm_oid, "_name", None)
    return name or str(certificate.signature_algorithm_oid.dotted_string)
