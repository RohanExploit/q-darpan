"""Command-line interface.

The CLI is the product surface: air-gapped operators run this, not the API. Exit
codes are meaningful so that a quarterly scan can be wired into a job scheduler
and its outcome acted on without parsing output.

    0  clean
    1  usage or configuration error
    2  partial failure -- some targets errored, results still written
    3  no targets resolved
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional, Sequence

from . import diff as diff_module
from . import evidence as evidence_module
from .canonical import POLICY_DIR, default_registry
from .collectors import ALL_SURFACES
from .ir import DEFAULT_CONFIDENCE_FLOOR
from .journal import TOOL_VERSION, RunJournal
from .pipeline import analyse, write_outputs
from .risk import Policy
from .scan import OfflineViolation, ScanOptions, scan

EXIT_OK = 0
EXIT_USAGE = 1
EXIT_PARTIAL = 2
EXIT_NO_TARGETS = 3


def _run_id(reproducible: bool) -> str:
    if reproducible:
        return "reproducible"
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="qdarpan",
        description=(
            "Discover cryptographic assets, emit a CycloneDX 1.7 CBOM, and rank a "
            "post-quantum migration queue. Runs entirely on-premises."
        ),
    )
    parser.add_argument("--version", action="version", version="qdarpan %s" % TOOL_VERSION)
    subparsers = parser.add_subparsers(dest="command", required=True)

    scan_parser = subparsers.add_parser("scan", help="scan targets and write a CBOM")
    scan_parser.add_argument(
        "targets",
        nargs="+",
        help="directories, binaries, container tarballs or host:port endpoints",
    )
    scan_parser.add_argument("--out", default="runs", help="output directory (default: runs)")
    scan_parser.add_argument(
        "--surface",
        default=None,
        help="comma-separated subset of: %s" % ",".join(ALL_SURFACES),
    )
    scan_parser.add_argument("--resume", action="store_true", help="reuse and extend the latest run")
    scan_parser.add_argument(
        "--reproducible",
        action="store_true",
        help="deterministic output: fixed timestamp and content-derived serial number",
    )
    scan_parser.add_argument(
        "--offline", action="store_true", help="refuse every network surface"
    )
    scan_parser.add_argument(
        "--include-low-confidence",
        action="store_true",
        help="emit findings below the confidence floor into the CBOM as well",
    )
    scan_parser.add_argument(
        "--confidence-floor",
        type=float,
        default=None,
        help="override the policy confidence floor (default %.2f)" % DEFAULT_CONFIDENCE_FLOOR,
    )
    scan_parser.add_argument("--policy", default=None, help="path to an operator policy file")
    scan_parser.add_argument("--workers", type=int, default=None, help="worker threads")
    scan_parser.add_argument("--tls-timeout", type=float, default=6.0, help="TLS timeout in seconds")
    scan_parser.add_argument(
        "--probe-groups",
        action="store_true",
        help="probe which key-agreement groups each TLS endpoint accepts (one connection per group)",
    )
    scan_parser.add_argument(
        "--probe-versions",
        action="store_true",
        help="probe which TLS versions each endpoint accepts (one connection per version)",
    )
    scan_parser.add_argument("--quiet", action="store_true", help="suppress progress output")

    report_parser = subparsers.add_parser(
        "report", help="re-render a report from an existing run without rescanning"
    )
    report_parser.add_argument("run_dir")
    report_parser.add_argument("--format", choices=("md", "json"), default="md")
    report_parser.add_argument("--policy", default=None)

    diff_parser = subparsers.add_parser("diff", help="compare two CBOMs")
    diff_parser.add_argument("before")
    diff_parser.add_argument("after")
    diff_parser.add_argument("--format", choices=("md", "json"), default="md")

    evidence_parser = subparsers.add_parser("evidence", help="build an auditor evidence pack")
    evidence_parser.add_argument("run_dir")
    evidence_parser.add_argument("-o", "--output", default="evidence-pack.zip")

    policy_parser = subparsers.add_parser("policy", help="inspect or validate policy files")
    policy_parser.add_argument("action", choices=("show", "validate"))
    policy_parser.add_argument("--policy", default=None)

    serve_parser = subparsers.add_parser("serve", help="run the local API and dashboard")
    serve_parser.add_argument("--host", default="127.0.0.1")
    serve_parser.add_argument("--port", type=int, default=8787)
    serve_parser.add_argument("--runs", default="runs")

    return parser


def _surfaces(value: Optional[str]) -> Sequence[str]:
    if not value:
        return ALL_SURFACES
    return tuple(part.strip() for part in value.split(",") if part.strip())


def cmd_scan(args) -> int:
    run_root = Path(args.out)
    run_dir = run_root / _run_id(args.reproducible)

    if args.resume and run_root.is_dir():
        existing = sorted((p for p in run_root.iterdir() if p.is_dir()), reverse=True)
        if existing:
            run_dir = existing[0]

    options = ScanOptions(
        surfaces=_surfaces(args.surface),
        surfaces_explicit=bool(args.surface),
        offline=args.offline,
        resume=args.resume,
        workers=args.workers,
        tls_timeout=args.tls_timeout,
        probe_groups=args.probe_groups,
        probe_versions=args.probe_versions,
    )

    progress = None if args.quiet else (lambda message: print("  " + message, file=sys.stderr))

    try:
        summary = scan(args.targets, run_dir, options, progress=progress)
    except (OfflineViolation, ValueError) as exc:
        print("error: %s" % exc, file=sys.stderr)
        return EXIT_USAGE

    if summary.targets_scanned == 0 and summary.targets_skipped == 0:
        print("error: no scannable targets resolved", file=sys.stderr)
        return EXIT_NO_TARGETS

    policy = Policy.load(Path(args.policy)) if args.policy else Policy.load()
    floor = args.confidence_floor if args.confidence_floor is not None else policy.confidence_floor

    journal = RunJournal.open(run_dir)
    analysis = analyse(journal, policy=policy)
    paths = write_outputs(
        analysis,
        run_dir,
        reproducible=args.reproducible,
        include_low_confidence=args.include_low_confidence,
        confidence_floor=floor,
        scan_summary=summary.to_dict(),
    )

    print("")
    print("Q-DARPAN %s" % TOOL_VERSION)
    print("  run              %s" % run_dir)
    print("  targets scanned  %d (%d skipped as unchanged)" % (summary.targets_scanned, summary.targets_skipped))
    print("  raw findings     %d" % summary.findings)
    print("  distinct assets  %d" % len(analysis.merged))
    print("  errors           %d" % summary.errors)
    print("")

    from .risk import TIER_ORDER, summarise

    counts = summarise(analysis.assessments)
    for tier in sorted(counts, key=lambda t: TIER_ORDER.get(t, 9)):
        if counts[tier]:
            print("  %-9s %d" % (tier, counts[tier]))
    print("")
    print("  CBOM             %s" % paths["cbom"])
    print("  report           %s" % paths["report_md"])

    return EXIT_PARTIAL if summary.partial else EXIT_OK


def cmd_report(args) -> int:
    run_dir = Path(args.run_dir)
    if not (run_dir / "findings.jsonl").exists():
        print("error: %s does not look like a run directory" % run_dir, file=sys.stderr)
        return EXIT_USAGE

    policy = Policy.load(Path(args.policy)) if args.policy else Policy.load()
    analysis = analyse(RunJournal.open(run_dir), policy=policy)
    print(analysis.markdown() if args.format == "md" else analysis.json())
    return EXIT_OK


def cmd_diff(args) -> int:
    before, after = Path(args.before), Path(args.after)
    for path in (before, after):
        if not path.exists():
            print("error: %s does not exist" % path, file=sys.stderr)
            return EXIT_USAGE

    result = diff_module.compare_files(before, after)
    if args.format == "json":
        print(json.dumps(result.to_dict(), indent=2, sort_keys=True))
    else:
        print(diff_module.to_markdown(result))
    return EXIT_OK


def cmd_evidence(args) -> int:
    run_dir = Path(args.run_dir)
    if not run_dir.is_dir():
        print("error: %s is not a directory" % run_dir, file=sys.stderr)
        return EXIT_USAGE
    output = evidence_module.build(run_dir, Path(args.output))
    print("evidence pack written to %s" % output)
    return EXIT_OK


def cmd_policy(args) -> int:
    path = Path(args.policy) if args.policy else (POLICY_DIR / "pqc_policy.json")
    try:
        policy = Policy.load(path)
        registry = default_registry()
    except Exception as exc:  # noqa: BLE001 - report the fault, do not traceback
        print("error: %s" % exc, file=sys.stderr)
        return EXIT_USAGE

    if args.action == "validate":
        print("policy %s: ok" % path)
        print("algorithm registry version %s, %d families" % (registry.version, len(registry.families())))
        return EXIT_OK

    print(json.dumps(policy.raw(), indent=2, sort_keys=True))
    return EXIT_OK


def cmd_serve(args) -> int:
    try:
        import uvicorn

        from .api import create_app
    except ImportError:
        print(
            "error: the API extra is not installed. Install with: pip install qdarpan[api]",
            file=sys.stderr,
        )
        return EXIT_USAGE

    app = create_app(Path(args.runs))
    uvicorn.run(app, host=args.host, port=args.port, log_level="warning")
    return EXIT_OK


_COMMANDS = {
    "scan": cmd_scan,
    "report": cmd_report,
    "diff": cmd_diff,
    "evidence": cmd_evidence,
    "policy": cmd_policy,
    "serve": cmd_serve,
}


def main(argv: Optional[List[str]] = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    return _COMMANDS[args.command](args)


if __name__ == "__main__":
    raise SystemExit(main())
