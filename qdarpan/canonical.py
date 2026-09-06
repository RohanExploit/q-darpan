"""Canonicalisation of raw algorithm detections into registry-backed facts.

Collectors see wildly different spellings of the same thing: ``EVP_aes_256_gcm``
in C, ``AES/GCM/NoPadding`` in Java JCA, ``prime256v1`` in an X.509 certificate,
``TLS_AES_256_GCM_SHA384`` in a negotiated cipher suite. All of them have to
collapse onto one canonical name before deduplication can work, otherwise the
normaliser reports the same key four times.

Everything factual -- security levels, quantum status, OIDs -- lives in
``policy/algorithms.json`` rather than in code, so an operator can audit or
extend the registry without reading Python.
"""

from __future__ import annotations

import functools
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping, Optional

from .ir import Primitive

POLICY_DIR = Path(__file__).parent / "policy"

#: How a family plus its distinguishing parameter renders as a display name.
#: Presentation only -- the registry stays free of formatting concerns.
NAME_TEMPLATES = {
    "SHA-2": "SHA-{p}",
    "SHA-3": "SHA3-{p}",
    "TLS": "TLS{p}",
    "X25519": "X25519",
    "HMAC": "HMAC",
    "PBKDF2": "PBKDF2",
    "HKDF": "HKDF",
    "RC4": "RC4",
    "DES": "DES",
    "3DES": "3DES",
    "MD5": "MD5",
    "SHA-1": "SHA-1",
    "ChaCha20": "ChaCha20",
    "Blowfish": "Blowfish",
}

#: Families where an encryption mode is worth carrying in the display name.
MODE_BEARING_PRIMITIVES = {"block-cipher", "stream-cipher", "ae"}

_KEY_SIZE_IN_NAME = re.compile(r"(?:^|[-_])(\d{2,5})(?:$|[-_])")
_PUNCTUATION = re.compile(r"[^a-z0-9+]")


def _squash(value: str) -> str:
    """Punctuation-free lowercase form used for cross-ecosystem alias matching."""
    return _PUNCTUATION.sub("", str(value).strip().lower())


class UnknownAlgorithm(Exception):
    """Raised when a raw name cannot be resolved to a registry family."""


@dataclass(frozen=True)
class CanonicalAlgorithm:
    """A raw detection resolved against the registry.

    ``name`` is what appears in the CBOM and in reports; ``family`` is the
    registry key that the risk engine and recommender look up.
    """

    name: str
    family: str
    primitive: Primitive
    parameters: Mapping[str, Any]
    oid: Optional[str]
    security_bits: int
    quantum_security_bits: int
    quantum_status: str
    classical_status: str
    classical_note: Optional[str] = None
    nist_level: Optional[int] = None
    standard: Optional[str] = None

    @property
    def is_quantum_vulnerable(self) -> bool:
        return self.quantum_status in ("broken", "weakened")

    @property
    def is_classically_unsound(self) -> bool:
        return self.classical_status in ("broken", "disallowed", "deprecated")


class Registry:
    """Read-only view over ``algorithms.json``."""

    def __init__(self, data: Mapping[str, Any]):
        self._families = data["families"]
        self._aliases = data["aliases"]
        self._curve_aliases = data["curve_aliases"]
        self.version = data.get("version", "unknown")
        # Spellings differ by ecosystem: a Java MessageDigest asks for
        # "SHA-256", OpenSSL calls it "sha256", a certificate OID description
        # says "sha256WithRSAEncryption". Indexing aliases and family keys by a
        # punctuation-free form lets all three land on the same entry.
        self._squashed = {}
        for key, family in self._aliases.items():
            self._squashed.setdefault(_squash(key), family)
        for key in self._families:
            self._squashed.setdefault(_squash(key), key)

    @classmethod
    def load(cls, path: Optional[Path] = None) -> "Registry":
        path = path or (POLICY_DIR / "algorithms.json")
        with open(path, encoding="utf-8") as handle:
            return cls(json.load(handle))

    # -- lookup helpers ---------------------------------------------------

    def families(self):
        return dict(self._families)

    def _direct(self, candidate: str) -> Optional[str]:
        """One lookup attempt: exact key, alias, or punctuation-free alias."""
        if candidate in self._families:
            return candidate
        lowered = candidate.strip().lower()
        if lowered in self._aliases:
            return self._aliases[lowered]
        return self._squashed.get(_squash(candidate))

    def resolve_family(self, raw: str) -> Optional[str]:
        """Map any spelling of an algorithm onto a registry family key.

        Tries the whole string first, then peels trailing segments:
        ``aes-256-gcm`` becomes ``aes-256`` and then ``aes``. Peeling from the
        right works because every convention in the wild puts the family first
        and the qualifiers after it.
        """
        direct = self._direct(raw)
        if direct:
            return direct

        parts = [p for p in re.split(r"[-_/\s]+", raw.strip().lower()) if p]
        while len(parts) > 1:
            parts.pop()
            candidate = "-".join(parts)
            resolved = self._direct(candidate)
            if resolved:
                return resolved
        return None

    def normalise_curve(self, raw: str) -> str:
        return self._curve_aliases.get(str(raw).strip().lower(), str(raw))

    def entry(self, family: str) -> Mapping[str, Any]:
        try:
            return self._families[family]
        except KeyError as exc:
            raise UnknownAlgorithm(family) from exc

    # -- canonicalisation -------------------------------------------------

    def canonicalise(
        self,
        raw_name: str,
        parameters: Optional[Mapping[str, Any]] = None,
    ) -> CanonicalAlgorithm:
        """Resolve a raw detection into a :class:`CanonicalAlgorithm`.

        Unresolvable parameters are left absent rather than guessed. A family
        default is only applied where the standard itself defines one (an
        unqualified ``ML-KEM`` means ML-KEM-768 in practice); a bare ``RSA``
        with no key size stays a bare ``RSA`` so that a report never invents a
        2048-bit key that nobody observed.
        """
        family = self.resolve_family(raw_name)
        if family is None:
            raise UnknownAlgorithm(raw_name)

        entry = self.entry(family)
        params = dict(parameters or {})

        param_field = entry.get("parameter")
        param_value = self._extract_parameter(family, entry, raw_name, params)

        if param_field and param_value is not None:
            params[param_field] = param_value

        if "curve" in params:
            params["curve"] = self.normalise_curve(params["curve"])
            param_value = params["curve"] if param_field == "curve" else param_value

        primitive = Primitive(entry.get("primitive", "unknown"))
        name = self._render_name(family, entry, param_value, params, primitive)

        bits = self._lookup_scale(entry.get("security_bits"), param_value)
        qbits = self._lookup_scale(entry.get("quantum_security_bits"), param_value)
        if qbits is None:
            # Shor reduces asymmetric schemes to nothing; Grover halves
            # symmetric ones. Where the registry does not state a quantum
            # level, derive it from the stated attack.
            attack = entry.get("quantum_attack")
            status = entry.get("quantum_status")
            if status == "safe":
                qbits = bits or 0
            elif attack == "shor":
                qbits = 0
            elif attack == "grover":
                qbits = (bits or 0) // 2
            else:
                qbits = bits or 0

        return CanonicalAlgorithm(
            name=name,
            family=family,
            primitive=primitive,
            parameters=params,
            oid=self._lookup_oid(entry, param_value),
            security_bits=int(bits or 0),
            quantum_security_bits=int(qbits or 0),
            quantum_status=entry.get("quantum_status", "unknown"),
            classical_status=entry.get("classical_status", "unknown"),
            classical_note=entry.get("classical_note"),
            nist_level=self._lookup_scale(entry.get("nist_level"), param_value),
            standard=entry.get("standard"),
        )

    # -- internals --------------------------------------------------------

    def _extract_parameter(
        self,
        family: str,
        entry: Mapping[str, Any],
        raw_name: str,
        params: Mapping[str, Any],
    ):
        """Find the family's distinguishing parameter.

        Priority: an explicitly supplied parameter, then a size embedded in the
        raw name, then the standard's own default where one exists.
        """
        field = entry.get("parameter")
        if not field:
            return None

        if params.get(field) is not None:
            value = params[field]
            return self.normalise_curve(value) if field == "curve" else value

        if field == "key_size":
            match = _KEY_SIZE_IN_NAME.search(raw_name)
            if match:
                candidate = int(match.group(1))
                table = entry.get("security_bits", {})
                if str(candidate) in table:
                    return candidate
        elif field == "curve":
            curve = self.normalise_curve(raw_name)
            if curve in entry.get("security_bits", {}):
                return curve
        elif field == "version":
            match = re.search(r"(\d+\.\d+)", raw_name)
            if match:
                return match.group(1)

        # Only fall back to a default where the standard defines one. Families
        # like RSA deliberately have none: an unqualified RSA detection must
        # not silently become RSA-2048.
        return entry.get("default_parameter")

    def _render_name(
        self,
        family: str,
        entry: Mapping[str, Any],
        param_value: Any,
        params: Mapping[str, Any],
        primitive: Primitive,
    ) -> str:
        template = NAME_TEMPLATES.get(family)
        if template is not None:
            base = template.format(p=param_value) if "{p}" in template else template
        elif param_value is not None:
            base = "%s-%s" % (family, param_value)
        else:
            base = family

        mode = params.get("mode")
        if mode and primitive.value in MODE_BEARING_PRIMITIVES:
            base = "%s-%s" % (base, str(mode).upper())
        return base

    @staticmethod
    def _lookup_scale(table: Optional[Mapping[str, Any]], param_value: Any):
        """Read a parameter-keyed table, honouring the ``*`` wildcard entry."""
        if not table:
            return None
        if param_value is not None and str(param_value) in table:
            return table[str(param_value)]
        return table.get("*")

    @staticmethod
    def _lookup_oid(entry: Mapping[str, Any], param_value: Any) -> Optional[str]:
        oids = entry.get("oids")
        if not oids:
            return None
        if param_value is not None and str(param_value) in oids:
            return oids[str(param_value)]
        return oids.get("*")


@functools.lru_cache(maxsize=1)
def default_registry() -> Registry:
    """Process-wide registry, loaded once."""
    return Registry.load()
