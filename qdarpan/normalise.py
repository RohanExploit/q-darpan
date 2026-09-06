"""Cross-surface deduplication.

Four collectors looking at the same system will report the same algorithm more
than once: the AST sees ``EVP_aes_256_gcm`` in the source, the ELF collector
finds the AES S-box in the shipped binary, the container collector finds the
same binary inside an image layer. Those are one fact with three witnesses, not
three facts.

Merging them is also what makes confidence meaningful. A single string literal
is weak evidence; the same algorithm corroborated from source *and* binary is
much stronger, and the noisy-OR combination in :func:`~qdarpan.ir.combine_confidence`
says so arithmetically.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
from typing import Any, Dict, Iterable, List, Sequence, Tuple

from .ir import (
    CryptoFinding,
    Evidence,
    EvidenceTier,
    Location,
    Surface,
    combine_confidence,
)

#: Evidence tiers in descending strength. Used to choose which witness a merged
#: finding presents as its primary location.
_TIER_ORDER = {
    tier: index
    for index, tier in enumerate(
        (
            EvidenceTier.NEGOTIATED,
            EvidenceTier.DIRECT_API_CALL,
            EvidenceTier.LINKED_LIBRARY_PINNED,
            EvidenceTier.CRYPTO_CONSTANT,
            EvidenceTier.LINKED_LIBRARY_UNPINNED,
            EvidenceTier.STRING_LITERAL,
            EvidenceTier.FILENAME_METADATA,
        )
    )
}


@dataclass(frozen=True)
class MergedFinding:
    """One cryptographic fact plus every place it was witnessed.

    The single :class:`~qdarpan.ir.CryptoFinding` inside carries the merged
    evidence and the combined confidence; ``locations`` keeps every sighting so
    an auditor can still see all of them, which a plain merge would discard.
    """

    finding: CryptoFinding
    locations: Tuple[Location, ...]
    surfaces: Tuple[Surface, ...]
    collectors: Tuple[str, ...]

    @property
    def confidence(self) -> float:
        return self.finding.confidence

    @property
    def corroborated(self) -> bool:
        """True when more than one surface saw this asset."""
        return len(self.surfaces) > 1

    def to_dict(self) -> dict:
        data = self.finding.to_dict()
        data["locations"] = [
            {
                "surface": loc.surface.value,
                "path": loc.path,
                "line": loc.line,
                "offset": loc.offset,
                "layer_digest": loc.layer_digest,
                "endpoint": loc.endpoint,
            }
            for loc in self.locations
        ]
        data["surfaces"] = [s.value for s in self.surfaces]
        data["collectors"] = list(self.collectors)
        data["corroborated"] = self.corroborated
        return data


def _tier_rank(evidence: Evidence) -> int:
    return _TIER_ORDER.get(evidence.tier, len(_TIER_ORDER))


def _dedupe_evidence(records: Iterable[Evidence]) -> Tuple[Evidence, ...]:
    """Drop exact duplicate witnesses.

    Two collectors firing the same matcher on the same snippet is one witness,
    not two -- otherwise noisy-OR would inflate confidence for free.
    """
    seen = {}
    for record in records:
        key = (record.tier, record.matcher_id, record.snippet)
        if key not in seen:
            seen[key] = record
    return tuple(sorted(seen.values(), key=lambda e: (_tier_rank(e), e.matcher_id)))


def _merge_parameters(findings: Sequence[CryptoFinding]) -> Dict[str, Any]:
    """Union parameters, preferring values from the strongest witness.

    Findings that share a canonical key already agree on the significant
    parameters; this fills in the incidental ones (padding seen only in source,
    validity dates seen only on the wire).
    """
    merged: Dict[str, Any] = {}
    ordered = sorted(
        findings,
        key=lambda f: min((_tier_rank(e) for e in f.evidence), default=len(_TIER_ORDER)),
    )
    for finding in reversed(ordered):
        for key, value in finding.parameters.items():
            if value is not None:
                merged[key] = value
    return merged


def merge(findings: Iterable[CryptoFinding]) -> List[MergedFinding]:
    """Collapse findings that share a canonical key.

    Returns results sorted by descending confidence then by bom-ref, so that
    output ordering is deterministic and does not depend on which collector
    happened to finish first.
    """
    groups: Dict[tuple, List[CryptoFinding]] = {}
    for finding in findings:
        groups.setdefault(finding.canonical_key(), []).append(finding)

    merged: List[MergedFinding] = []
    for group in groups.values():
        evidence = _dedupe_evidence(
            record for finding in group for record in finding.evidence
        )
        confidence = combine_confidence(evidence)

        primary = min(
            group,
            key=lambda f: (
                min((_tier_rank(e) for e in f.evidence), default=len(_TIER_ORDER)),
                f.location.describe(),
            ),
        )

        locations = tuple(
            sorted(
                {f.location for f in group},
                key=lambda loc: (loc.surface.value, loc.describe()),
            )
        )
        surfaces = tuple(sorted({loc.surface for loc in locations}, key=lambda s: s.value))
        collectors = tuple(sorted({f.collector for f in group}))

        functions = frozenset().union(*(f.functions for f in group)) if group else frozenset()
        library = next((f.library for f in group if f.library), None)
        oid = next((f.oid for f in group if f.oid), None)

        combined = replace(
            primary,
            evidence=evidence,
            parameters=_merge_parameters(group),
            functions=functions,
            library=library,
            oid=oid,
            confidence=confidence,
        )
        merged.append(
            MergedFinding(
                finding=combined,
                locations=locations,
                surfaces=surfaces,
                collectors=collectors,
            )
        )

    merged.sort(key=lambda m: (-m.confidence, m.finding.bom_ref()))
    return merged


def blast_radius(merged: Iterable[MergedFinding]) -> Dict[str, int]:
    """Count how many distinct targets each algorithm name appears in.

    This is what turns a flat inventory into a priority order: an algorithm
    present in one repository and one present in ninety are not the same
    migration problem, even at identical risk.
    """
    radius: Dict[str, set] = {}
    for item in merged:
        radius.setdefault(item.finding.name, set()).add(item.finding.target_id)
    return {name: len(targets) for name, targets in sorted(radius.items())}
