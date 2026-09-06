"""Append-only run journal.

A scan of a real estate -- hundreds of repositories, thousands of TLS endpoints
-- will be interrupted. The journal exists so that an interrupted scan resumes
instead of restarting, and so that a quarterly rescan skips targets whose
content has not changed.

It is also the evidence of record. The CBOM is a summary; ``findings.jsonl``
holds every raw witness including the ones filtered out below the confidence
floor, which is what an auditor needs to check our work.
"""

from __future__ import annotations

import hashlib
import json
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional

from .ir import CollectorError, CryptoFinding

TOOL_NAME = "qdarpan"
TOOL_VERSION = "0.1.0"

#: Files larger than this are hashed by size and mtime rather than by content.
#: Hashing a 2 GB disk image to decide whether to rescan it costs more than the
#: rescan would.
_FULL_HASH_LIMIT = 64 * 1024 * 1024

#: Directories that never contain crypto worth reporting but do contain enough
#: files to dominate a scan's runtime.
SKIP_DIRECTORIES = frozenset(
    {
        ".git", ".hg", ".svn", "node_modules", "__pycache__", ".venv", "venv",
        ".tox", ".mypy_cache", ".pytest_cache", "dist", "build", ".idea", ".vscode",
    }
)


def content_hash(path: Path) -> str:
    """Cheap, stable fingerprint of a file or directory.

    For a directory this is a hash over the sorted list of (relative path, size,
    mtime) triples rather than over file contents. That is enough to decide
    "has this repository changed since last quarter", and it does not require
    reading a whole source tree twice.
    """
    digest = hashlib.sha256()
    if path.is_file():
        stat = path.stat()
        if stat.st_size <= _FULL_HASH_LIMIT:
            with open(path, "rb") as handle:
                for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                    digest.update(chunk)
        else:
            digest.update(("%d:%d" % (stat.st_size, int(stat.st_mtime))).encode())
        return digest.hexdigest()

    if path.is_dir():
        for root, dirs, files in os.walk(path):
            dirs[:] = sorted(d for d in dirs if d not in SKIP_DIRECTORIES)
            for name in sorted(files):
                item = Path(root) / name
                try:
                    stat = item.stat()
                except OSError:
                    continue
                rel = item.relative_to(path).as_posix()
                digest.update(("%s:%d:%d\n" % (rel, stat.st_size, int(stat.st_mtime))).encode())
        return digest.hexdigest()

    # Non-filesystem target such as host:port -- identity is the string itself.
    digest.update(str(path).encode())
    return digest.hexdigest()


@dataclass
class TargetRecord:
    """One scanned thing and the state of its scan."""

    target_id: str
    kind: str
    content_hash: str
    status: str = "pending"  # pending | complete | error
    findings: int = 0
    errors: int = 0

    def to_dict(self) -> dict:
        return {
            "target_id": self.target_id,
            "kind": self.kind,
            "content_hash": self.content_hash,
            "status": self.status,
            "findings": self.findings,
            "errors": self.errors,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "TargetRecord":
        return cls(
            target_id=data["target_id"],
            kind=data["kind"],
            content_hash=data["content_hash"],
            status=data.get("status", "pending"),
            findings=int(data.get("findings", 0)),
            errors=int(data.get("errors", 0)),
        )


@dataclass
class Manifest:
    """What a run scanned, with what tool and policy.

    Recorded so that a CBOM can be reproduced later, and so that ``--resume``
    can tell which targets are genuinely unchanged.
    """

    run_id: str
    tool: str = TOOL_NAME
    tool_version: str = TOOL_VERSION
    policy_hash: str = ""
    registry_version: str = ""
    reproducible: bool = False
    targets: Dict[str, TargetRecord] = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "run_id": self.run_id,
            "tool": self.tool,
            "tool_version": self.tool_version,
            "policy_hash": self.policy_hash,
            "registry_version": self.registry_version,
            "reproducible": self.reproducible,
            "targets": [record.to_dict() for record in self.targets.values()],
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Manifest":
        manifest = cls(
            run_id=data["run_id"],
            tool=data.get("tool", TOOL_NAME),
            tool_version=data.get("tool_version", TOOL_VERSION),
            policy_hash=data.get("policy_hash", ""),
            registry_version=data.get("registry_version", ""),
            reproducible=bool(data.get("reproducible", False)),
        )
        for entry in data.get("targets", []):
            record = TargetRecord.from_dict(entry)
            manifest.targets[record.target_id] = record
        return manifest


class RunJournal:
    """The on-disk state of one scan.

    Writes are appends and are flushed per record. A process killed mid-scan
    leaves a journal that is still valid JSONL up to the last complete line,
    which is exactly what resume needs.
    """

    def __init__(self, run_dir: Path, manifest: Optional[Manifest] = None):
        self.run_dir = Path(run_dir)
        self.run_dir.mkdir(parents=True, exist_ok=True)
        self.findings_path = self.run_dir / "findings.jsonl"
        self.errors_path = self.run_dir / "errors.jsonl"
        self.manifest_path = self.run_dir / "manifest.json"
        self.manifest = manifest or Manifest(run_id=self.run_dir.name)

    # -- lifecycle --------------------------------------------------------

    @classmethod
    def open(cls, run_dir: Path) -> "RunJournal":
        """Reopen an existing run for resume or reporting."""
        run_dir = Path(run_dir)
        manifest_path = run_dir / "manifest.json"
        manifest = None
        if manifest_path.exists():
            with open(manifest_path, encoding="utf-8") as handle:
                manifest = Manifest.from_dict(json.load(handle))
        return cls(run_dir, manifest)

    def save_manifest(self) -> None:
        payload = json.dumps(self.manifest.to_dict(), indent=2, sort_keys=True)
        with open(self.manifest_path, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(payload + "\n")

    # -- writing ----------------------------------------------------------

    def record_finding(self, finding: CryptoFinding) -> None:
        self._append(self.findings_path, finding.to_dict())
        record = self.manifest.targets.get(finding.target_id)
        if record is not None:
            record.findings += 1

    def record_error(self, error: CollectorError) -> None:
        self._append(self.errors_path, error.to_dict())
        record = self.manifest.targets.get(error.target_id)
        if record is not None:
            record.errors += 1

    @staticmethod
    def _append(path: Path, payload: Dict[str, Any]) -> None:
        line = json.dumps(payload, sort_keys=True, separators=(",", ":"))
        with open(path, "a", encoding="utf-8", newline="\n") as handle:
            handle.write(line + "\n")
            handle.flush()

    # -- reading ----------------------------------------------------------

    def findings(self) -> Iterator[CryptoFinding]:
        """Replay the journal.

        A truncated final line -- the signature of a killed process -- is
        skipped rather than raised, because the whole point of the journal is
        that it survives an interruption.
        """
        if not self.findings_path.exists():
            return
        with open(self.findings_path, encoding="utf-8") as handle:
            for line in handle:
                line = line.strip()
                if not line:
                    continue
                try:
                    yield CryptoFinding.from_dict(json.loads(line))
                except (json.JSONDecodeError, KeyError):
                    continue

    def errors(self) -> List[dict]:
        if not self.errors_path.exists():
            return []
        out = []
        with open(self.errors_path, encoding="utf-8") as handle:
            for line in handle:
                line = line.strip()
                if not line:
                    continue
                try:
                    out.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
        return out

    # -- resume -----------------------------------------------------------

    def should_skip(self, target_id: str, current_hash: str) -> bool:
        """True when a completed target's content is unchanged since last run."""
        record = self.manifest.targets.get(target_id)
        return bool(
            record and record.status == "complete" and record.content_hash == current_hash
        )

    def register_target(self, target_id: str, kind: str, current_hash: str) -> TargetRecord:
        record = self.manifest.targets.get(target_id)
        if record is None or record.content_hash != current_hash:
            record = TargetRecord(target_id=target_id, kind=kind, content_hash=current_hash)
            self.manifest.targets[target_id] = record
        return record

    def complete_target(self, target_id: str) -> None:
        record = self.manifest.targets.get(target_id)
        if record is not None:
            record.status = "complete" if record.errors == 0 else "error"
