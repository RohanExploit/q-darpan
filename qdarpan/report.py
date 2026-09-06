"""Human-readable output.

The CBOM is for machines and auditors; this is for the person who has to
actually do the migration. It leads with the ranked queue rather than with an
inventory, because the inventory is not the decision -- the order is.
"""

from __future__ import annotations

import json
from typing import Any, Dict, List, Optional, Sequence

from .normalise import MergedFinding
from .recommend import QueueEntry, summarise_costs
from .risk import RiskAssessment, TIER_ORDER, summarise

_TIER_LABEL = {
    "critical": "CRITICAL",
    "high": "HIGH",
    "medium": "MEDIUM",
    "low": "LOW",
    "pq-safe": "PQ-SAFE",
}


def to_json(
    queue: Sequence[QueueEntry],
    merged: Sequence[MergedFinding],
    assessments: Sequence[RiskAssessment],
    *,
    scan_summary: Optional[Dict[str, Any]] = None,
    errors: Optional[Sequence[dict]] = None,
) -> str:
    payload = {
        "summary": {
            "assets": len(merged),
            "by_tier": summarise(assessments),
            "costs": summarise_costs(queue),
            "scan": scan_summary or {},
            "errors": len(errors or []),
        },
        "queue": [entry.to_dict() for entry in queue],
        "errors": list(errors or []),
    }
    return json.dumps(payload, indent=2, sort_keys=True)


def to_markdown(
    queue: Sequence[QueueEntry],
    merged: Sequence[MergedFinding],
    assessments: Sequence[RiskAssessment],
    *,
    scan_summary: Optional[Dict[str, Any]] = None,
    errors: Optional[Sequence[dict]] = None,
    limit: int = 40,
) -> str:
    lines: List[str] = []
    counts = summarise(assessments)
    costs = summarise_costs(queue)

    lines.append("# Q-DARPAN cryptographic inventory")
    lines.append("")
    lines.append("## Summary")
    lines.append("")
    lines.append("| Metric | Value |")
    lines.append("| --- | --- |")
    libraries = [m for m in merged if m.finding.asset_kind.value == "library"]
    lines.append("| Distinct cryptographic assets | %d |" % (len(merged) - len(libraries)))
    lines.append("| Crypto libraries inventoried | %d |" % len(libraries))
    lines.append("| Assets needing migration | %d |" % costs["assets_needing_migration"])
    for tier in sorted(counts, key=lambda t: TIER_ORDER.get(t, 9)):
        lines.append("| %s | %d |" % (_TIER_LABEL.get(tier, tier), counts[tier]))
    if scan_summary:
        lines.append("| Targets scanned | %s |" % scan_summary.get("targets_scanned", "?"))
        lines.append("| Targets skipped (unchanged) | %s |" % scan_summary.get("targets_skipped", "?"))
        lines.append("| Collector errors | %s |" % scan_summary.get("errors", 0))
    lines.append("")

    if costs["recommended_targets"]:
        lines.append("### Recommended post-quantum targets")
        lines.append("")
        for target, count in costs["recommended_targets"].items():
            lines.append("- **%s** for %d asset(s)" % (target, count))
        lines.append("")

    lines.append("## Migration queue")
    lines.append("")
    lines.append(
        "Ordered by risk tier, then by how many targets share the asset, then by "
        "the byte cost of the swap."
    )
    lines.append("")
    lines.append("| # | Tier | Asset | Target | Seen in | Conf. | Replace with | Cost |")
    lines.append("| --- | --- | --- | --- | --- | --- | --- | --- |")

    for index, entry in enumerate(queue[:limit], start=1):
        assessment = entry.assessment
        recommendation = entry.recommendation
        replace_with = "-"
        if recommendation:
            replace_with = recommendation.target
            if recommendation.hybrid:
                replace_with += " (hybrid %s)" % recommendation.hybrid
        cost = "-"
        if recommendation and recommendation.size_deltas:
            cost = _headline_delta(recommendation.size_deltas).describe()
        lines.append(
            "| %d | %s | %s | %s | %d target(s) | %.2f | %s | %s |"
            % (
                index,
                _TIER_LABEL.get(assessment.tier, assessment.tier),
                assessment.name,
                _shorten(assessment.target_id),
                entry.blast_radius,
                assessment.finding.confidence,
                replace_with,
                cost,
            )
        )
    if len(queue) > limit:
        lines.append("")
        lines.append("_%d further asset(s) omitted from this table; the full set is in the JSON report._" % (len(queue) - limit))
    lines.append("")

    urgent = [e for e in queue if e.assessment.tier in ("critical", "high")]
    if urgent:
        lines.append("## Why these are urgent")
        lines.append("")
        for entry in urgent[:limit]:
            assessment = entry.assessment
            lines.append("### %s -- %s" % (assessment.name, _TIER_LABEL.get(assessment.tier)))
            lines.append("")
            lines.append("- **Target:** %s" % assessment.target_id)
            lines.append("- **Rationale:** %s" % assessment.rationale)
            lines.append(
                "- **Evidence:** %s (confidence %.2f, %s)"
                % (
                    ", ".join(sorted({e.tier.value for e in assessment.finding.finding.evidence})),
                    assessment.finding.confidence,
                    "corroborated across %d surfaces" % len(assessment.finding.surfaces)
                    if assessment.finding.corroborated
                    else "single surface",
                )
            )
            for location in assessment.finding.locations[:5]:
                lines.append("  - `%s`" % location.describe())
            if assessment.mosca:
                mosca = assessment.mosca
                lines.append(
                    "- **Mosca:** X=%dy migration + Y=%dy shelf life; trips %d of %d scenarios"
                    % (
                        mosca.migration_years,
                        mosca.shelf_life_years,
                        mosca.scenarios_tripped,
                        mosca.total_scenarios,
                    )
                )
                for name, scenario in mosca.scenarios.items():
                    lines.append(
                        "  - %s (Z=%dy): %s, margin %+dy"
                        % (
                            name,
                            scenario["z_years_to_crqc"],
                            "TRIPS" if scenario["trips"] else "holds",
                            scenario["margin_years"],
                        )
                    )
            for deadline in assessment.deadlines:
                lines.append(
                    "- **Deadline:** %s (%d years remaining)"
                    % (deadline.label, deadline.years_remaining)
                )
            if entry.recommendation:
                rec = entry.recommendation
                lines.append("- **Migrate to:** %s%s" % (rec.target, " (%s)" % rec.standard if rec.standard else ""))
                if rec.hybrid:
                    lines.append("  - Hybrid option: %s (RFC 10024)" % rec.hybrid)
                if rec.alternative:
                    lines.append("  - Alternative: %s" % rec.alternative)
                if rec.rationale:
                    lines.append("  - %s" % rec.rationale)
                for delta in rec.size_deltas:
                    lines.append("  - %s" % delta.describe())
                if rec.latency_note:
                    lines.append("  - %s" % rec.latency_note)
            lines.append("")

    if errors:
        lines.append("## Coverage gaps")
        lines.append("")
        lines.append(
            "These targets or files could not be read. Coverage is stated rather than "
            "silently reduced."
        )
        lines.append("")
        for error in list(errors)[:limit]:
            lines.append(
                "- `%s` (%s/%s): %s"
                % (
                    error.get("path") or error.get("target_id"),
                    error.get("collector"),
                    error.get("phase"),
                    error.get("reason"),
                )
            )
        if len(errors) > limit:
            lines.append("- _%d further error(s) in `errors.jsonl`._" % (len(errors) - limit))
        lines.append("")

    return "\n".join(lines)


#: Which size delta to headline, most operationally significant first. The
#: bytes that cross the network every handshake matter more to a migration plan
#: than the private key sitting in an HSM, even when the private key grew more.
_HEADLINE_FIELDS = ("signature", "ciphertext", "public_key", "private_key")


def _headline_delta(deltas):
    by_field = {d.field: d for d in deltas}
    for field in _HEADLINE_FIELDS:
        if field in by_field:
            return by_field[field]
    return max(deltas, key=lambda d: d.delta)


def _shorten(value: str, width: int = 44) -> str:
    if len(value) <= width:
        return value
    return "..." + value[-(width - 3):]
