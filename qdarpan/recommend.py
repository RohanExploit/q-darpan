"""Migration recommendations and the ranked queue.

Discovery on its own produces a list. What an operator actually needs is an
order: which swap to do first, and what it will cost. The ranking is risk tier,
then blast radius, then migration cost -- because a critical algorithm in
ninety components outranks a critical algorithm in one, and among equals the
cheaper swap goes first.

Byte deltas come from the FIPS standards themselves. They matter: ML-DSA-65
signatures are 3309 bytes against ECDSA-P256's 64, and a migration plan that
does not budget for that will fail in the field rather than on paper.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional, Sequence

from .canonical import Registry, UnknownAlgorithm, default_registry
from .ir import CryptoFunction
from .normalise import MergedFinding, blast_radius
from .risk import TIER_ORDER, RiskAssessment

POLICY_DIR = Path(__file__).parent / "policy"

_PUNCTUATION = re.compile(r"[^a-z0-9+]")


def _squash(value: str) -> str:
    return _PUNCTUATION.sub("", str(value).strip().lower())

#: Observed crypto function -> the recommendation-table roles it implies, most
#: specific first. Keygen and generate are deliberately absent: generating a key
#: says nothing about whether it will sign or encapsulate.
_FUNCTION_ROLES = {
    CryptoFunction.SIGN: ("signature",),
    CryptoFunction.VERIFY: ("signature",),
    CryptoFunction.ENCAPSULATE: ("kem", "key-agree"),
    CryptoFunction.DECAPSULATE: ("kem", "key-agree"),
    CryptoFunction.KEYDERIVE: ("key-agree", "kdf"),
    CryptoFunction.ENCRYPT: ("pke", "block-cipher", "stream-cipher", "ae"),
    CryptoFunction.DECRYPT: ("pke", "block-cipher", "stream-cipher", "ae"),
    CryptoFunction.DIGEST: ("hash",),
    CryptoFunction.TAG: ("mac",),
}


def roles_for(functions) -> List[str]:
    """Turn observed crypto functions into ordered recommendation-table roles."""
    roles: List[str] = []
    for function in sorted(functions, key=lambda f: f.value):
        for role in _FUNCTION_ROLES.get(function, ()):
            if role not in roles:
                roles.append(role)
    return roles


@dataclass(frozen=True)
class SizeDelta:
    """What the swap costs on the wire, in bytes."""

    field: str
    before: int
    after: int

    @property
    def delta(self) -> int:
        return self.after - self.before

    @property
    def ratio(self) -> Optional[float]:
        if self.before <= 0:
            return None
        return round(self.after / self.before, 1)

    def describe(self) -> str:
        if self.ratio is None:
            return "%s %d B -> %d B" % (self.field, self.before, self.after)
        return "%s %d B -> %d B (%+d B, %.1fx)" % (
            self.field,
            self.before,
            self.after,
            self.delta,
            self.ratio,
        )

    def to_dict(self) -> dict:
        return {
            "field": self.field,
            "before_bytes": self.before,
            "after_bytes": self.after,
            "delta_bytes": self.delta,
            "ratio": self.ratio,
        }


@dataclass(frozen=True)
class Recommendation:
    """What to replace an algorithm with, and what it costs."""

    target: str
    standard: Optional[str]
    hybrid: Optional[str]
    alternative: Optional[str]
    rationale: Optional[str]
    size_deltas: Sequence[SizeDelta]
    latency_note: Optional[str]

    def to_dict(self) -> dict:
        return {
            "target": self.target,
            "standard": self.standard,
            "hybrid": self.hybrid,
            "alternative": self.alternative,
            "rationale": self.rationale,
            "size_deltas": [d.to_dict() for d in self.size_deltas],
            "latency_note": self.latency_note,
        }


@dataclass(frozen=True)
class QueueEntry:
    """One row of the ranked migration queue."""

    assessment: RiskAssessment
    recommendation: Optional[Recommendation]
    blast_radius: int

    @property
    def cost_bytes(self) -> int:
        """Total added bytes across every measured field. Used as a tiebreak."""
        if not self.recommendation:
            return 0
        return sum(max(0, d.delta) for d in self.recommendation.size_deltas)

    def to_dict(self) -> dict:
        data = self.assessment.to_dict()
        data["blast_radius"] = self.blast_radius
        data["recommendation"] = (
            self.recommendation.to_dict() if self.recommendation else None
        )
        data["cost_bytes"] = self.cost_bytes
        return data


class CostModel:
    """Read-only view over ``migration_costs.json``."""

    def __init__(self, data: Mapping[str, Any]):
        self._sizes = data["algorithm_sizes_bytes"]
        self._squashed_sizes = {_squash(k): v for k, v in self._sizes.items()}
        self._recommendations = data["recommendations"]
        self._latency = data.get("latency_notes", {})
        self.version = data.get("version", "unknown")
        self.sources = data.get("sources", {})

    @classmethod
    def load(cls, path: Optional[Path] = None) -> "CostModel":
        path = path or (POLICY_DIR / "migration_costs.json")
        with open(path, encoding="utf-8") as handle:
            return cls(json.load(handle))

    def sizes(self, name: str) -> Mapping[str, int]:
        """Look up byte sizes, tolerating punctuation differences.

        The canonical display name is ``ECDSA-P-256`` while the FIPS size table
        is keyed ``ECDSA-P256``. Without this the cost column silently reads
        "-" for every elliptic-curve row, which is exactly the number an
        operator is here for.
        """
        if name in self._sizes:
            return self._sizes[name]
        return self._squashed_sizes.get(_squash(name), {})

    def _deltas(self, current: str, target: str) -> List[SizeDelta]:
        """Compare only the fields both algorithms actually define.

        A KEM has a ciphertext and no signature; a signature scheme is the
        reverse. Comparing across that boundary would manufacture numbers.
        """
        before = self.sizes(current)
        after = self.sizes(target)
        deltas = []
        for field in ("public_key", "private_key", "signature", "ciphertext"):
            if field in before and field in after:
                deltas.append(SizeDelta(field=field, before=before[field], after=after[field]))
        return deltas

    def recommend(
        self, family: str, current_name: str, roles: Sequence[str] = ()
    ) -> Optional[Recommendation]:
        """Pick the replacement for one algorithm in one role.

        ``roles`` are derived from the crypto functions actually observed at the
        call site. They decide the answer for families that serve more than one
        purpose: RSA is filed in the registry under ``pke``, but an RSA
        *signature* must migrate to ML-DSA, not to ML-KEM.

        With no observed role the first entry in the family's table wins.
        ``migration_costs.json`` orders each family by its likeliest deployed
        role for exactly this case -- RSA leads with ``signature`` because
        certificates are where it overwhelmingly turns up.
        """
        by_family = self._recommendations.get(family)
        if not by_family:
            return None

        entry = None
        for role in roles:
            if role in by_family:
                entry = by_family[role]
                break
        if entry is None:
            entry = next(iter(by_family.values()), None)
        if entry is None:
            return None

        target = entry["target"]
        if _squash(target) == _squash(current_name):
            return None
        return Recommendation(
            target=target,
            standard=entry.get("standard"),
            hybrid=entry.get("hybrid"),
            alternative=entry.get("alternative"),
            rationale=entry.get("rationale") or entry.get("alternative_rationale"),
            size_deltas=self._deltas(current_name, target),
            latency_note=self._latency.get(target),
        )


def recommend_for(
    assessment: RiskAssessment,
    *,
    costs: Optional[CostModel] = None,
    registry: Optional[Registry] = None,
) -> Optional[Recommendation]:
    """Find the replacement for one assessed finding."""
    costs = costs or CostModel.load()
    registry = registry or default_registry()

    finding = assessment.finding.finding
    try:
        canonical = registry.canonicalise(finding.name, finding.parameters)
    except UnknownAlgorithm:
        return None

    if canonical.quantum_status == "safe" and not canonical.is_classically_unsound:
        return None

    return costs.recommend(canonical.family, canonical.name, roles_for(finding.functions))


def build_queue(
    assessments: Sequence[RiskAssessment],
    merged: Sequence[MergedFinding],
    *,
    costs: Optional[CostModel] = None,
    registry: Optional[Registry] = None,
) -> List[QueueEntry]:
    """Rank assessed findings into the migration queue.

    Order: risk tier, then blast radius descending, then cheapest swap, then
    bom-ref for determinism.
    """
    costs = costs or CostModel.load()
    registry = registry or default_registry()
    radius = blast_radius(merged)

    entries = [
        QueueEntry(
            assessment=assessment,
            recommendation=recommend_for(assessment, costs=costs, registry=registry),
            blast_radius=radius.get(assessment.name, 1),
        )
        for assessment in assessments
    ]
    entries.sort(
        key=lambda e: (
            TIER_ORDER.get(e.assessment.tier, 9),
            -e.blast_radius,
            e.cost_bytes,
            e.assessment.finding.finding.bom_ref(),
        )
    )
    return entries


def actionable(entries: Sequence[QueueEntry]) -> List[QueueEntry]:
    """Only the rows that have somewhere to migrate to."""
    return [entry for entry in entries if entry.recommendation is not None]


def summarise_costs(entries: Sequence[QueueEntry]) -> Dict[str, Any]:
    """Estate-level totals for the report header."""
    actionable_entries = actionable(entries)
    targets = {}
    for entry in actionable_entries:
        target = entry.recommendation.target
        targets[target] = targets.get(target, 0) + 1
    return {
        "assets_needing_migration": len(actionable_entries),
        "recommended_targets": dict(sorted(targets.items())),
        "total_added_bytes_per_operation": sum(e.cost_bytes for e in actionable_entries),
    }
