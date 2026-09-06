"""CBOM-to-CBOM comparison.

A SOC does not run a discovery tool once. It runs it every quarter, and what it
needs from the second run is not another inventory -- it is the delta. What
crypto appeared, what disappeared, and what changed shape.

This works only because emission is deterministic: bom-refs are derived from
the canonical key, so the same asset carries the same reference across runs and
a diff compares like with like instead of comparing generated UUIDs.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional, Sequence, Tuple


@dataclass(frozen=True)
class AssetChange:
    """One asset whose properties differ between two runs."""

    bom_ref: str
    name: str
    target: Optional[str]
    changes: Mapping[str, Tuple[Any, Any]]

    def to_dict(self) -> dict:
        return {
            "bom_ref": self.bom_ref,
            "name": self.name,
            "target": self.target,
            "changes": {k: {"before": v[0], "after": v[1]} for k, v in self.changes.items()},
        }


@dataclass(frozen=True)
class CbomDiff:
    """The quarter-over-quarter delta."""

    appeared: Sequence[dict]
    disappeared: Sequence[dict]
    changed: Sequence[AssetChange]
    unchanged: int

    @property
    def has_changes(self) -> bool:
        return bool(self.appeared or self.disappeared or self.changed)

    def to_dict(self) -> dict:
        return {
            "summary": {
                "appeared": len(self.appeared),
                "disappeared": len(self.disappeared),
                "changed": len(self.changed),
                "unchanged": self.unchanged,
            },
            "appeared": list(self.appeared),
            "disappeared": list(self.disappeared),
            "changed": [c.to_dict() for c in self.changed],
        }


#: Properties worth diffing. Location strings churn constantly (a line moves
#: when someone adds an import) and would drown the signal, so they are not
#: compared -- their presence is what matters, not their coordinates.
_TRACKED_PROPERTIES = (
    "qdarpan:confidence",
    "qdarpan:surfaces",
    "qdarpan:collectors",
    "qdarpan:quantum-status",
    "qdarpan:classical-status",
    "qdarpan:corroborated",
)


def _index(document: Mapping[str, Any]) -> Dict[str, dict]:
    index = {}
    for component in document.get("components", []):
        ref = component.get("bom-ref") or component.get("bomRef")
        if ref:
            index[ref] = component
    return index


def _properties(component: Mapping[str, Any]) -> Dict[str, str]:
    return {
        prop.get("name"): prop.get("value")
        for prop in component.get("properties", [])
        if prop.get("name")
    }


def _describe(component: Mapping[str, Any]) -> dict:
    props = _properties(component)
    return {
        "bom_ref": component.get("bom-ref") or component.get("bomRef"),
        "name": component.get("name"),
        "target": props.get("qdarpan:target"),
        "confidence": props.get("qdarpan:confidence"),
        "quantum_status": props.get("qdarpan:quantum-status"),
        "surfaces": props.get("qdarpan:surfaces"),
    }


def compare(before: Mapping[str, Any], after: Mapping[str, Any]) -> CbomDiff:
    """Diff two loaded CBOM documents."""
    old = _index(before)
    new = _index(after)

    appeared = [_describe(new[ref]) for ref in sorted(set(new) - set(old))]
    disappeared = [_describe(old[ref]) for ref in sorted(set(old) - set(new))]

    changed: List[AssetChange] = []
    unchanged = 0
    for ref in sorted(set(old) & set(new)):
        old_props = _properties(old[ref])
        new_props = _properties(new[ref])
        deltas = {
            key: (old_props.get(key), new_props.get(key))
            for key in _TRACKED_PROPERTIES
            if old_props.get(key) != new_props.get(key)
        }
        if deltas:
            changed.append(
                AssetChange(
                    bom_ref=ref,
                    name=new[ref].get("name", ""),
                    target=new_props.get("qdarpan:target"),
                    changes=deltas,
                )
            )
        else:
            unchanged += 1

    return CbomDiff(
        appeared=appeared, disappeared=disappeared, changed=changed, unchanged=unchanged
    )


def compare_files(before_path: Path, after_path: Path) -> CbomDiff:
    with open(before_path, encoding="utf-8") as handle:
        before = json.load(handle)
    with open(after_path, encoding="utf-8") as handle:
        after = json.load(handle)
    return compare(before, after)


def to_markdown(diff: CbomDiff) -> str:
    lines = ["# CBOM diff", ""]
    lines.append("| Change | Count |")
    lines.append("| --- | --- |")
    lines.append("| Appeared | %d |" % len(diff.appeared))
    lines.append("| Disappeared | %d |" % len(diff.disappeared))
    lines.append("| Changed | %d |" % len(diff.changed))
    lines.append("| Unchanged | %d |" % diff.unchanged)
    lines.append("")

    if not diff.has_changes:
        lines.append("No cryptographic change between these two scans.")
        return "\n".join(lines)

    if diff.appeared:
        lines.append("## Appeared")
        lines.append("")
        for item in diff.appeared:
            lines.append(
                "- **%s** in `%s` (%s, confidence %s)"
                % (item["name"], item["target"], item["quantum_status"], item["confidence"])
            )
        lines.append("")

    if diff.disappeared:
        lines.append("## Disappeared")
        lines.append("")
        for item in diff.disappeared:
            lines.append("- **%s** in `%s`" % (item["name"], item["target"]))
        lines.append("")

    if diff.changed:
        lines.append("## Changed")
        lines.append("")
        for change in diff.changed:
            lines.append("- **%s** in `%s`" % (change.name, change.target))
            for key, (old, new) in sorted(change.changes.items()):
                lines.append("  - %s: `%s` -> `%s`" % (key, old, new))
        lines.append("")

    return "\n".join(lines)
