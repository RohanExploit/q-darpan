"""Intermediate representation shared by every part of Q-DARPAN.

Collectors produce :class:`CryptoFinding` objects and nothing else. The
normaliser, the CBOM emitter, the risk engine and the recommender all read
them. Keeping evidence and confidence first-class here -- rather than encoding
findings directly as CycloneDX components -- is what lets the pipeline dedupe
across surfaces, resume interrupted scans and stay testable collector by
collector.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass, field, replace
from enum import Enum
from typing import Any, Iterable, Mapping, Optional, Tuple


class AssetKind(str, Enum):
    """What sort of cryptographic asset a finding describes.

    Values match the CycloneDX 1.7 ``cryptoProperties.assetType`` vocabulary so
    that emission is a translation rather than an interpretation.
    """

    ALGORITHM = "algorithm"
    CERTIFICATE = "certificate"
    PROTOCOL = "protocol"
    RELATED_MATERIAL = "related-crypto-material"
    LIBRARY = "library"


class Primitive(str, Enum):
    """Cryptographic primitive, matching CycloneDX ``cryptoPrimitive``."""

    PKE = "pke"
    SIGNATURE = "signature"
    KEM = "kem"
    KEY_AGREE = "key-agree"
    HASH = "hash"
    BLOCK_CIPHER = "block-cipher"
    STREAM_CIPHER = "stream-cipher"
    MAC = "mac"
    KEY_WRAP = "key-wrap"
    AE = "ae"
    KDF = "kdf"
    DRBG = "drbg"
    XOF = "xof"
    COMBINER = "combiner"
    OTHER = "other"
    UNKNOWN = "unknown"


class CryptoFunction(str, Enum):
    """Observed use of an algorithm, matching CycloneDX ``cryptoFunctions``."""

    GENERATE = "generate"
    KEYGEN = "keygen"
    ENCRYPT = "encrypt"
    DECRYPT = "decrypt"
    SIGN = "sign"
    VERIFY = "verify"
    ENCAPSULATE = "encapsulate"
    DECAPSULATE = "decapsulate"
    DIGEST = "digest"
    TAG = "tag"
    KEYDERIVE = "keyderive"
    OTHER = "other"


class Surface(str, Enum):
    """Which collector surface produced a finding."""

    SOURCE = "source"
    ELF = "elf"
    CONTAINER = "container"
    TLS = "tls"


class EvidenceTier(str, Enum):
    """Strength of the observation behind a finding.

    Ordered strongest to weakest. ``NEGOTIATED`` outranks a source-level API
    call because it records something that actually happened on the wire rather
    than something inferred from code.
    """

    NEGOTIATED = "negotiated"
    DIRECT_API_CALL = "direct_api_call"
    LINKED_LIBRARY_PINNED = "linked_library_pinned"
    CRYPTO_CONSTANT = "crypto_constant"
    LINKED_LIBRARY_UNPINNED = "linked_library_unpinned"
    STRING_LITERAL = "string_literal"
    FILENAME_METADATA = "filename_metadata"


#: Base confidence contributed by each evidence tier. Published deliberately:
#: a reviewer must be able to check why a finding scored what it scored.
TIER_CONFIDENCE = {
    EvidenceTier.NEGOTIATED: 0.99,
    EvidenceTier.DIRECT_API_CALL: 0.95,
    EvidenceTier.LINKED_LIBRARY_PINNED: 0.80,
    EvidenceTier.CRYPTO_CONSTANT: 0.70,
    EvidenceTier.LINKED_LIBRARY_UNPINNED: 0.55,
    EvidenceTier.STRING_LITERAL: 0.40,
    EvidenceTier.FILENAME_METADATA: 0.30,
}

#: Confidence ceiling. Inferred evidence never reaches certainty, and even a
#: negotiated handshake is reported at the ceiling rather than at 1.0.
CONFIDENCE_CEILING = 0.99

#: Findings below this score are journaled but kept out of the CBOM unless the
#: operator asks for them. Sits above FILENAME_METADATA on purpose.
DEFAULT_CONFIDENCE_FLOOR = 0.35


@dataclass(frozen=True)
class Location:
    """Where a finding was observed.

    Only the fields relevant to the surface are populated; the rest stay
    ``None`` so that serialised findings do not carry misleading empty strings.
    """

    surface: Surface
    path: Optional[str] = None
    line: Optional[int] = None
    offset: Optional[int] = None
    layer_digest: Optional[str] = None
    endpoint: Optional[str] = None

    def describe(self) -> str:
        """Human-readable one-liner for reports and CLI output."""
        if self.endpoint:
            return self.endpoint
        parts = [self.path or "<unknown>"]
        if self.line is not None:
            parts.append(":%d" % self.line)
        elif self.offset is not None:
            parts.append("@0x%x" % self.offset)
        if self.layer_digest:
            parts.append(" (layer %s)" % self.layer_digest[:19])
        return "".join(parts)


@dataclass(frozen=True)
class Evidence:
    """Why we believe a finding is real.

    ``matcher_id`` names the rule or constant that fired, so a false positive
    can be traced to the exact detector responsible and fixed there.
    """

    tier: EvidenceTier
    matcher_id: str
    snippet: Optional[str] = None
    detail: Mapping[str, Any] = field(default_factory=dict)

    @property
    def base_confidence(self) -> float:
        return TIER_CONFIDENCE[self.tier]


@dataclass(frozen=True)
class CryptoFinding:
    """A single cryptographic observation about a single target.

    ``target_id`` participates in the dedupe key on purpose: the same algorithm
    in two repositories is two findings, while the same algorithm found in one
    repository by both the AST and ELF collectors is one finding carrying two
    evidence records.
    """

    target_id: str
    asset_kind: AssetKind
    name: str
    location: Location
    evidence: Tuple[Evidence, ...]
    collector: str
    primitive: Primitive = Primitive.UNKNOWN
    parameters: Mapping[str, Any] = field(default_factory=dict)
    oid: Optional[str] = None
    functions: frozenset = field(default_factory=frozenset)
    library: Optional[str] = None
    confidence: float = 0.0

    #: Parameters that change what an asset *is*, as opposed to where it was
    #: seen. Only these take part in the dedupe key.
    SIGNIFICANT_PARAMETERS = ("key_size", "curve", "mode", "padding", "hash", "version")

    def significant_parameters(self) -> Tuple[Tuple[str, str], ...]:
        """The subset of parameters that distinguishes one asset from another."""
        return tuple(
            sorted(
                (key, str(self.parameters[key]))
                for key in self.SIGNIFICANT_PARAMETERS
                if self.parameters.get(key) is not None
            )
        )

    def canonical_key(self) -> Tuple[Any, ...]:
        """Identity used for cross-surface deduplication."""
        return (
            self.target_id,
            self.asset_kind.value,
            self.name,
            self.significant_parameters(),
        )

    def bom_ref(self) -> str:
        """Stable, content-derived reference.

        Derived from the canonical key rather than generated randomly so that
        two scans of unchanged inputs produce byte-identical CBOMs.
        """
        payload = json.dumps(self.canonical_key(), sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()[:16]

    def with_confidence(self, value: float) -> "CryptoFinding":
        return replace(self, confidence=round(min(value, CONFIDENCE_CEILING), 4))

    def to_dict(self) -> dict:
        """Serialise for the JSONL journal."""
        data = asdict(self)
        data["asset_kind"] = self.asset_kind.value
        data["primitive"] = self.primitive.value
        data["functions"] = sorted(fn.value for fn in self.functions)
        data["location"]["surface"] = self.location.surface.value
        data["evidence"] = [
            {
                "tier": ev.tier.value,
                "matcher_id": ev.matcher_id,
                "snippet": ev.snippet,
                "detail": dict(ev.detail),
            }
            for ev in self.evidence
        ]
        data["parameters"] = dict(self.parameters)
        return data

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "CryptoFinding":
        """Inverse of :meth:`to_dict`, used when resuming a scan."""
        loc = dict(data["location"])
        loc["surface"] = Surface(loc["surface"])
        evidence = tuple(
            Evidence(
                tier=EvidenceTier(ev["tier"]),
                matcher_id=ev["matcher_id"],
                snippet=ev.get("snippet"),
                detail=ev.get("detail") or {},
            )
            for ev in data["evidence"]
        )
        return cls(
            target_id=data["target_id"],
            asset_kind=AssetKind(data["asset_kind"]),
            name=data["name"],
            location=Location(**loc),
            evidence=evidence,
            collector=data["collector"],
            primitive=Primitive(data.get("primitive", "unknown")),
            parameters=dict(data.get("parameters") or {}),
            oid=data.get("oid"),
            functions=frozenset(CryptoFunction(f) for f in data.get("functions") or ()),
            library=data.get("library"),
            confidence=float(data.get("confidence") or 0.0),
        )


@dataclass(frozen=True)
class CollectorError:
    """A recoverable failure during a scan.

    Collectors never abort a run. Whatever went wrong is recorded here so the
    run's coverage can be stated honestly instead of silently under-reported.
    """

    target_id: str
    collector: str
    phase: str
    reason: str
    path: Optional[str] = None

    def to_dict(self) -> dict:
        return asdict(self)


def combine_confidence(evidence: Iterable[Evidence]) -> float:
    """Combine evidence by noisy-OR.

    ``combined = 1 - product(1 - c_i)``, capped at the ceiling. Corroboration
    across surfaces raises confidence without ever asserting certainty, and a
    single negotiated handshake already sits at the ceiling -- which is correct,
    because we watched it happen.
    """
    complement = 1.0
    seen = False
    for ev in evidence:
        seen = True
        complement *= 1.0 - ev.base_confidence
    if not seen:
        return 0.0
    return round(min(1.0 - complement, CONFIDENCE_CEILING), 4)
