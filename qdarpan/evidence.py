"""Evidence pack construction.

A regulator asking "how do you know" should not have to take the CBOM's word
for it. The pack carries the raw journal, the policy that was in force, the
algorithm registry that was used, and the tool version -- everything needed to
re-derive the CBOM from the same inputs and check that we did not massage it.
"""

from __future__ import annotations

import hashlib
import json
import zipfile
from pathlib import Path
from typing import Dict, List, Optional

from .canonical import POLICY_DIR
from .journal import TOOL_NAME, TOOL_VERSION, RunJournal

#: Files copied out of a run directory, when present.
_RUN_ARTEFACTS = ("manifest.json", "findings.jsonl", "errors.jsonl", "cbom.json", "report.md", "report.json")

#: Policy files snapshotted so that a later reader sees the thresholds that
#: were actually applied, not whatever the repository holds today.
_POLICY_FILES = ("algorithms.json", "pqc_policy.json", "migration_costs.json")


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def build(run_dir: Path, output: Path, *, commit: Optional[str] = None) -> Path:
    """Zip a run into a self-contained evidence pack.

    Every file is listed in ``pack.json`` with its SHA-256 so that tampering
    with the pack after the fact is detectable.
    """
    run_dir = Path(run_dir)
    output = Path(output)
    output.parent.mkdir(parents=True, exist_ok=True)

    journal = RunJournal.open(run_dir)
    inventory: List[Dict[str, str]] = []

    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED) as pack:
        for name in _RUN_ARTEFACTS:
            source = run_dir / name
            if not source.exists():
                continue
            pack.write(source, arcname="run/%s" % name)
            inventory.append(
                {"path": "run/%s" % name, "sha256": _sha256(source), "bytes": str(source.stat().st_size)}
            )

        for name in _POLICY_FILES:
            source = POLICY_DIR / name
            if not source.exists():
                continue
            pack.write(source, arcname="policy/%s" % name)
            inventory.append(
                {"path": "policy/%s" % name, "sha256": _sha256(source), "bytes": str(source.stat().st_size)}
            )

        metadata = {
            "tool": TOOL_NAME,
            "tool_version": TOOL_VERSION,
            "commit": commit,
            "run_id": journal.manifest.run_id,
            "registry_version": journal.manifest.registry_version,
            "targets": [record.to_dict() for record in journal.manifest.targets.values()],
            "contents": inventory,
            "note": (
                "findings.jsonl is the evidence of record and includes findings below the "
                "confidence floor that were deliberately excluded from cbom.json."
            ),
        }
        pack.writestr("pack.json", json.dumps(metadata, indent=2, sort_keys=True))

    return output
