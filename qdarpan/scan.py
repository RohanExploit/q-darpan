"""Scan orchestration.

Targets are classified, matched to the collectors that can handle them, and run
through a bounded worker pool. Every finding and every failure is appended to
the run journal as it happens rather than at the end, which is what makes an
interrupted scan resumable and a long scan observable.
"""

from __future__ import annotations

import os
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Dict, Iterable, List, Optional, Sequence

from .canonical import Registry, default_registry
from .collectors import (
    ALL_SURFACES,
    COLLECTOR_TYPES,
    NETWORK_SURFACES,
    Collector,
    Target,
    TargetKind,
    classify,
)
from .ir import CollectorError, CryptoFinding
from .journal import RunJournal, content_hash


class OfflineViolation(Exception):
    """Raised when a network surface is requested during an offline scan.

    A hard error rather than a warning: an operator who passed ``--offline``
    has been told there will be no traffic, and silently downgrading that
    promise to a warning is how enclaves get violated.
    """


@dataclass
class ScanOptions:
    surfaces: Sequence[str] = ALL_SURFACES
    #: True when the operator named surfaces explicitly. Only then is asking
    #: for a network surface under --offline an error rather than a filter.
    surfaces_explicit: bool = False
    offline: bool = False
    resume: bool = False
    workers: Optional[int] = None
    tls_timeout: float = 6.0
    probe_groups: bool = False
    probe_versions: bool = False


@dataclass
class ScanSummary:
    """What a run actually managed to do, stated plainly."""

    targets_scanned: int
    targets_skipped: int
    findings: int
    errors: int

    @property
    def partial(self) -> bool:
        return self.errors > 0

    def to_dict(self) -> dict:
        return {
            "targets_scanned": self.targets_scanned,
            "targets_skipped": self.targets_skipped,
            "findings": self.findings,
            "errors": self.errors,
            "partial": self.partial,
        }


def default_workers() -> int:
    """Leave headroom. A scan should not make the analyst's laptop unusable."""
    return max(2, min(8, (os.cpu_count() or 4) - 1))


def build_collectors(
    options: ScanOptions, registry: Optional[Registry] = None
) -> List[Collector]:
    registry = registry or default_registry()
    requested = list(options.surfaces or ALL_SURFACES)

    unknown = [s for s in requested if s not in COLLECTOR_TYPES]
    if unknown:
        raise ValueError("unknown surface(s): %s" % ", ".join(sorted(unknown)))

    if options.offline:
        blocked = [s for s in requested if s in NETWORK_SURFACES]
        if blocked and options.surfaces_explicit:
            raise OfflineViolation(
                "surface(s) %s require network access but --offline was given"
                % ", ".join(sorted(blocked))
            )
        requested = [s for s in requested if s not in NETWORK_SURFACES]

    collectors: List[Collector] = []
    for surface in requested:
        cls = COLLECTOR_TYPES[surface]
        if surface == "tls":
            collectors.append(
                cls(
                    registry=registry,
                    timeout=options.tls_timeout,
                    probe_groups=options.probe_groups,
                    probe_versions=options.probe_versions,
                )
            )
        else:
            collectors.append(cls(registry=registry))
    return collectors


def scan(
    raw_targets: Iterable[str],
    run_dir: Path,
    options: Optional[ScanOptions] = None,
    registry: Optional[Registry] = None,
    progress: Optional[Callable[[str], None]] = None,
) -> ScanSummary:
    """Run every applicable collector over every target.

    Returns a summary rather than the findings themselves: the journal on disk
    is the result, and holding an estate's worth of findings in memory to
    return them would defeat the point of streaming to it.
    """
    options = options or ScanOptions()
    registry = registry or default_registry()
    collectors = build_collectors(options, registry)

    journal = RunJournal.open(run_dir) if options.resume else RunJournal(run_dir)
    journal.manifest.registry_version = registry.version

    targets = [classify(raw) for raw in raw_targets]
    known = [t for t in targets if t.kind != TargetKind.UNKNOWN]
    for unknown_target in (t for t in targets if t.kind == TargetKind.UNKNOWN):
        journal.record_error(
            CollectorError(
                target_id=unknown_target.target_id,
                collector="scan",
                phase="classify",
                reason="target is neither an existing path nor a host:port endpoint",
            )
        )

    units: List[tuple] = []
    skipped = 0
    for target in known:
        digest = content_hash(target.path if target.path else Path(target.target_id))
        if options.resume and journal.should_skip(target.target_id, digest):
            skipped += 1
            if progress:
                progress("skip %s (unchanged)" % target.target_id)
            continue
        journal.register_target(target.target_id, target.kind, digest)
        for collector in collectors:
            if collector.supports(target):
                units.append((collector, target))

    findings = 0
    errors = len(journal.errors())
    workers = options.workers or default_workers()

    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {
            pool.submit(collector.safe_collect, target): (collector, target)
            for collector, target in units
        }
        for future in as_completed(futures):
            collector, target = futures[future]
            results = future.result()
            for item in results:
                if isinstance(item, CryptoFinding):
                    journal.record_finding(item)
                    findings += 1
                else:
                    journal.record_error(item)
                    errors += 1
            if progress:
                progress(
                    "%s %s -> %d result(s)"
                    % (collector.name, target.target_id, len(results))
                )

    for target in known:
        journal.complete_target(target.target_id)
    journal.manifest.reproducible = False
    journal.save_manifest()

    return ScanSummary(
        targets_scanned=len(known) - skipped,
        targets_skipped=skipped,
        findings=findings,
        errors=errors,
    )
