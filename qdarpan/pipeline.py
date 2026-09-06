"""The read-side pipeline: journal in, CBOM and ranked queue out.

Kept separate from :mod:`qdarpan.scan` so that reporting can be re-run over an
existing journal without rescanning anything -- which is what an operator does
when they change a policy threshold and want to see the effect.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional, Sequence

from . import cbom as cbom_module
from . import report as report_module
from .canonical import Registry, default_registry
from .ir import DEFAULT_CONFIDENCE_FLOOR
from .journal import RunJournal
from .normalise import MergedFinding, merge
from .recommend import CostModel, QueueEntry, build_queue
from .risk import Policy, RiskAssessment, assess_all


@dataclass
class Analysis:
    """Everything derived from one run's journal."""

    merged: List[MergedFinding]
    assessments: List[RiskAssessment]
    queue: List[QueueEntry]
    errors: List[dict]

    def cbom_json(self, *, reproducible: bool = False, include_low_confidence: bool = False,
                  confidence_floor: float = DEFAULT_CONFIDENCE_FLOOR) -> str:
        return cbom_module.emit(
            self.merged,
            reproducible=reproducible,
            include_low_confidence=include_low_confidence,
            confidence_floor=confidence_floor,
        )

    def markdown(self, scan_summary: Optional[dict] = None) -> str:
        return report_module.to_markdown(
            self.queue, self.merged, self.assessments,
            scan_summary=scan_summary, errors=self.errors,
        )

    def json(self, scan_summary: Optional[dict] = None) -> str:
        return report_module.to_json(
            self.queue, self.merged, self.assessments,
            scan_summary=scan_summary, errors=self.errors,
        )


def analyse(
    journal: RunJournal,
    *,
    policy: Optional[Policy] = None,
    registry: Optional[Registry] = None,
    costs: Optional[CostModel] = None,
    criticality_by_target: Optional[dict] = None,
) -> Analysis:
    """Merge, score and rank a run's findings."""
    registry = registry or default_registry()
    policy = policy or Policy.load()
    costs = costs or CostModel.load()

    merged = merge(journal.findings())
    assessments = assess_all(
        merged, policy=policy, registry=registry, criticality_by_target=criticality_by_target
    )
    queue = build_queue(assessments, merged, costs=costs, registry=registry)
    return Analysis(
        merged=merged, assessments=assessments, queue=queue, errors=journal.errors()
    )


def write_outputs(
    analysis: Analysis,
    run_dir: Path,
    *,
    reproducible: bool = False,
    include_low_confidence: bool = False,
    confidence_floor: float = DEFAULT_CONFIDENCE_FLOOR,
    scan_summary: Optional[dict] = None,
) -> dict:
    """Write cbom.json, report.md and report.json into the run directory."""
    run_dir = Path(run_dir)
    run_dir.mkdir(parents=True, exist_ok=True)

    paths = {
        "cbom": run_dir / "cbom.json",
        "report_md": run_dir / "report.md",
        "report_json": run_dir / "report.json",
    }

    _write(
        paths["cbom"],
        analysis.cbom_json(
            reproducible=reproducible,
            include_low_confidence=include_low_confidence,
            confidence_floor=confidence_floor,
        ),
    )
    _write(paths["report_md"], analysis.markdown(scan_summary))
    _write(paths["report_json"], analysis.json(scan_summary))
    return paths


def _write(path: Path, text: str) -> None:
    # newline="\n" throughout: a CBOM that differs only by line endings between
    # a Windows analyst laptop and a Linux CI runner is not a real difference,
    # but it does break byte-identical reproducibility checks.
    with open(path, "w", encoding="utf-8", newline="\n") as handle:
        handle.write(text if text.endswith("\n") else text + "\n")
