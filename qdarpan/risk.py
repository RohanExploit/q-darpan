"""Quantum risk scoring.

Two clocks run at once and they are not the same clock.

The first is Mosca's inequality, ``X + Y > Z``: if the time to migrate plus the
time the data must stay secret exceeds the time until a cryptographically
relevant quantum computer, you are already late. Z is genuinely contested, so
Q-DARPAN refuses to pick one -- it evaluates against the optimistic, median and
pessimistic ends of the Global Risk Institute expert range and reports which of
them trip.

The second is regulatory. NIST IR 8547 deprecates 112-bit RSA and ECC after
2030 and disallows them after 2035; the DST National Quantum Mission expects
vendor CBOMs from FY 2027-28. An asset can be perfectly calm under Mosca and
still be on a deadline, so both are reported side by side.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional, Sequence, Tuple

from .canonical import Registry, UnknownAlgorithm, default_registry
from .normalise import MergedFinding

POLICY_DIR = Path(__file__).parent / "policy"

CRITICAL = "critical"
HIGH = "high"
MEDIUM = "medium"
LOW = "low"
PQ_SAFE = "pq-safe"

#: Ordering used everywhere a queue is sorted. Lower sorts first.
TIER_ORDER = {CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3, PQ_SAFE: 4}


@dataclass(frozen=True)
class MoscaResult:
    """The inequality evaluated against every scenario.

    ``scenarios_tripped`` is the honest headline: three of three means the
    asset is late under every expert view, one of three means only the
    pessimists are worried.
    """

    migration_years: int
    shelf_life_years: int
    scenarios: Mapping[str, Dict[str, Any]]

    @property
    def scenarios_tripped(self) -> int:
        return sum(1 for s in self.scenarios.values() if s["trips"])

    @property
    def total_scenarios(self) -> int:
        return len(self.scenarios)

    @property
    def trips_median(self) -> bool:
        median = self.scenarios.get("median")
        return bool(median and median["trips"])

    @property
    def trips_all(self) -> bool:
        return self.scenarios_tripped == self.total_scenarios and self.total_scenarios > 0

    def to_dict(self) -> dict:
        return {
            "x_migration_years": self.migration_years,
            "y_shelf_life_years": self.shelf_life_years,
            "scenarios": {k: dict(v) for k, v in self.scenarios.items()},
            "scenarios_tripped": self.scenarios_tripped,
            "total_scenarios": self.total_scenarios,
        }


@dataclass(frozen=True)
class Deadline:
    """One regulatory milestone as it applies to one asset."""

    id: str
    year: int
    label: str
    source: str
    years_remaining: int

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "year": self.year,
            "label": self.label,
            "source": self.source,
            "years_remaining": self.years_remaining,
        }


@dataclass(frozen=True)
class RiskAssessment:
    """Everything the migration queue needs to know about one finding."""

    finding: MergedFinding
    tier: str
    rationale: str
    quantum_status: str
    classical_status: str
    security_bits: int
    quantum_security_bits: int
    mosca: Optional[MoscaResult]
    deadlines: Tuple[Deadline, ...]
    criticality: str

    @property
    def name(self) -> str:
        return self.finding.finding.name

    @property
    def target_id(self) -> str:
        return self.finding.finding.target_id

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "target_id": self.target_id,
            "bom_ref": self.finding.finding.bom_ref(),
            "tier": self.tier,
            "rationale": self.rationale,
            "confidence": self.finding.confidence,
            "quantum_status": self.quantum_status,
            "classical_status": self.classical_status,
            "security_bits": self.security_bits,
            "quantum_security_bits": self.quantum_security_bits,
            "criticality": self.criticality,
            "mosca": self.mosca.to_dict() if self.mosca else None,
            "deadlines": [d.to_dict() for d in self.deadlines],
            "surfaces": [s.value for s in self.finding.surfaces],
            "locations": [loc.describe() for loc in self.finding.locations],
        }


class Policy:
    """Operator-tunable inputs to the risk model."""

    def __init__(self, data: Mapping[str, Any]):
        self._data = data
        self.reference_year = int(data.get("reference_year", 2026))
        self.timeline = data["quantum_timeline"]
        self.milestones = data.get("regulatory_milestones", [])
        self.criticality_tiers = data["criticality_tiers"]
        self.default_criticality = data.get("default_criticality", "high")
        self.effort = data["migration_effort_years"]
        self.confidence_floor = float(data.get("confidence_floor", 0.35))

    @classmethod
    def load(cls, path: Optional[Path] = None) -> "Policy":
        path = path or (POLICY_DIR / "pqc_policy.json")
        with open(path, encoding="utf-8") as handle:
            return cls(json.load(handle))

    def raw(self) -> Mapping[str, Any]:
        return self._data

    def shelf_life(self, criticality: str) -> int:
        tier = self.criticality_tiers.get(criticality) or self.criticality_tiers[
            self.default_criticality
        ]
        return int(tier["data_shelf_life_years"])

    def migration_years(self, surface: str, asset_kind: str) -> int:
        """Worst case of the surface and asset-kind estimates.

        Deliberately pessimistic: under-estimating migration time is the
        failure mode that makes Mosca's inequality look comfortable when it is
        not.
        """
        by_surface = self.effort.get("by_surface", {}).get(surface)
        by_kind = self.effort.get("by_asset_kind", {}).get(asset_kind)
        candidates = [v for v in (by_surface, by_kind) if v is not None]
        if not candidates:
            return int(self.effort.get("default", 3))
        return int(max(candidates))


def evaluate_mosca(
    policy: Policy, migration_years: int, shelf_life_years: int
) -> MoscaResult:
    """Run ``X + Y > Z`` against every scenario in the policy."""
    scenarios = {}
    for name, scenario in policy.timeline["scenarios"].items():
        z = int(scenario["years_to_crqc"])
        total = migration_years + shelf_life_years
        scenarios[name] = {
            "z_years_to_crqc": z,
            "label": scenario.get("label", name),
            "trips": total > z,
            "margin_years": z - total,
        }
    return MoscaResult(
        migration_years=migration_years,
        shelf_life_years=shelf_life_years,
        scenarios=scenarios,
    )


def _deadlines(policy: Policy, quantum_vulnerable: bool, security_bits: int) -> Tuple[Deadline, ...]:
    """Select the milestones that actually bind this asset."""
    out: List[Deadline] = []
    for milestone in policy.milestones:
        applies = milestone.get("applies_to", "all")
        if applies == "quantum_vulnerable" and not quantum_vulnerable:
            continue
        if applies == "quantum_vulnerable_112" and not (
            quantum_vulnerable and 0 < security_bits <= 112
        ):
            continue
        out.append(
            Deadline(
                id=milestone["id"],
                year=int(milestone["year"]),
                label=milestone["label"],
                source=milestone.get("source", ""),
                years_remaining=int(milestone["year"]) - policy.reference_year,
            )
        )
    out.sort(key=lambda d: d.year)
    return tuple(out)


def assess(
    item: MergedFinding,
    *,
    policy: Optional[Policy] = None,
    registry: Optional[Registry] = None,
    criticality: Optional[str] = None,
) -> RiskAssessment:
    """Score a single merged finding."""
    policy = policy or Policy.load()
    registry = registry or default_registry()
    criticality = criticality or policy.default_criticality
    finding = item.finding

    try:
        canonical = registry.canonicalise(finding.name, finding.parameters)
        quantum_status = canonical.quantum_status
        classical_status = canonical.classical_status
        security_bits = canonical.security_bits
        quantum_bits = canonical.quantum_security_bits
        classical_note = canonical.classical_note
    except UnknownAlgorithm:
        # An unrecognised algorithm is a gap in the registry, not a safe asset.
        # Report it as unknown rather than quietly grading it PQ-safe.
        quantum_status = "unknown"
        classical_status = "unknown"
        security_bits = 0
        quantum_bits = 0
        classical_note = None

    quantum_vulnerable = quantum_status in ("broken", "weakened")
    surface = item.surfaces[0].value if item.surfaces else "source"
    migration_years = policy.migration_years(surface, finding.asset_kind.value)
    shelf_life = policy.shelf_life(criticality)

    mosca = (
        evaluate_mosca(policy, migration_years, shelf_life) if quantum_vulnerable else None
    )
    deadlines = _deadlines(policy, quantum_vulnerable, security_bits)

    tier, rationale = _tier(
        quantum_status=quantum_status,
        classical_status=classical_status,
        classical_note=classical_note,
        mosca=mosca,
    )

    return RiskAssessment(
        finding=item,
        tier=tier,
        rationale=rationale,
        quantum_status=quantum_status,
        classical_status=classical_status,
        security_bits=security_bits,
        quantum_security_bits=quantum_bits,
        mosca=mosca,
        deadlines=deadlines,
        criticality=criticality,
    )


def _tier(
    *,
    quantum_status: str,
    classical_status: str,
    classical_note: Optional[str],
    mosca: Optional[MoscaResult],
) -> Tuple[str, str]:
    """Combine the two clocks into one reported tier.

    Classical brokenness outranks everything: an asset using MD5 does not need
    a quantum computer to be in trouble, and saying so first keeps the report
    honest about which problem is urgent today.
    """
    if classical_status in ("broken", "disallowed"):
        note = classical_note or "Already unsound under classical cryptanalysis."
        return CRITICAL, note

    if quantum_status == "unknown":
        return MEDIUM, "Algorithm not in the registry; classify manually before dismissing."

    if quantum_status == "safe":
        return PQ_SAFE, "Not quantum-vulnerable at current understanding."

    if mosca is None:
        return LOW, "Quantum-vulnerable but no migration window computed."

    if mosca.trips_all:
        return (
            CRITICAL,
            "Mosca's inequality trips under all %d scenarios (X=%dy + Y=%dy)."
            % (mosca.total_scenarios, mosca.migration_years, mosca.shelf_life_years),
        )
    if mosca.trips_median:
        return (
            HIGH,
            "Mosca's inequality trips under the median scenario (%d of %d)."
            % (mosca.scenarios_tripped, mosca.total_scenarios),
        )
    if mosca.scenarios_tripped:
        return (
            MEDIUM,
            "Mosca's inequality trips only under the pessimistic scenario (%d of %d)."
            % (mosca.scenarios_tripped, mosca.total_scenarios),
        )
    if quantum_status == "weakened":
        return LOW, "Grover halves the effective key length but the margin still holds."
    return LOW, "Quantum-vulnerable but the migration window is not yet closing."


def assess_all(
    merged: Sequence[MergedFinding],
    *,
    policy: Optional[Policy] = None,
    registry: Optional[Registry] = None,
    criticality_by_target: Optional[Mapping[str, str]] = None,
) -> List[RiskAssessment]:
    """Score every finding, ordered most urgent first."""
    policy = policy or Policy.load()
    registry = registry or default_registry()
    criticality_by_target = criticality_by_target or {}

    results = [
        assess(
            item,
            policy=policy,
            registry=registry,
            criticality=criticality_by_target.get(item.finding.target_id),
        )
        for item in merged
    ]
    results.sort(
        key=lambda r: (TIER_ORDER.get(r.tier, 9), -r.finding.confidence, r.finding.finding.bom_ref())
    )
    return results


def summarise(assessments: Sequence[RiskAssessment]) -> Dict[str, int]:
    """Count findings per tier, in tier order."""
    counts = {tier: 0 for tier in TIER_ORDER}
    for assessment in assessments:
        counts[assessment.tier] = counts.get(assessment.tier, 0) + 1
    return counts
