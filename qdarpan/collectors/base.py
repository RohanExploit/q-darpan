"""Collector protocol and target classification.

Every collector answers the same two questions -- can I handle this target, and
what did I find in it -- and none of them may raise. A scan of a real estate
will hit unreadable files, truncated archives and hosts that do not answer;
those are expected conditions that get recorded, not exceptions that abandon
the other 2,299 targets.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Iterator, List, Optional, Union

from ..ir import CollectorError, CryptoFinding, Surface

Result = Union[CryptoFinding, CollectorError]

#: Skip anything larger than this. A 500 MB firmware blob is worth scanning; a
#: 4 GB VM disk image inside a repository is not, and reading it would dominate
#: the run.
MAX_FILE_BYTES = 256 * 1024 * 1024

SKIP_DIRECTORIES = frozenset(
    {
        ".git", ".hg", ".svn", "node_modules", "__pycache__", ".venv", "venv",
        ".tox", ".mypy_cache", ".pytest_cache", ".idea", ".vscode",
    }
)

_ENDPOINT = re.compile(r"^(?:\[(?P<v6>[0-9a-fA-F:]+)\]|(?P<host>[A-Za-z0-9._-]+)):(?P<port>\d{1,5})$")

CONTAINER_SUFFIXES = (".tar", ".tar.gz", ".tgz", ".oci")


class TargetKind:
    DIRECTORY = "directory"
    FILE = "file"
    CONTAINER = "container"
    ENDPOINT = "endpoint"
    UNKNOWN = "unknown"


@dataclass(frozen=True)
class Target:
    """Something to scan, classified so collectors can opt in.

    ``target_id`` is the stable identity that ends up in every finding and in
    the dedupe key, so it is normalised here once rather than in four
    collectors.
    """

    target_id: str
    kind: str
    path: Optional[Path] = None
    host: Optional[str] = None
    port: Optional[int] = None

    @property
    def endpoint(self) -> Optional[str]:
        if self.host is None or self.port is None:
            return None
        return "%s:%d" % (self.host, self.port)


def classify(raw: str) -> Target:
    """Work out what a command-line target actually is.

    Filesystem paths win over the ``host:port`` pattern, because a directory
    literally named ``example.com:443`` should still be scanned as a directory.
    """
    path = Path(raw)
    if path.exists():
        if path.is_dir():
            if (path / "oci-layout").exists() or (path / "index.json").exists():
                return Target(target_id=path.as_posix(), kind=TargetKind.CONTAINER, path=path)
            return Target(target_id=path.as_posix(), kind=TargetKind.DIRECTORY, path=path)
        lowered = path.name.lower()
        if any(lowered.endswith(suffix) for suffix in CONTAINER_SUFFIXES):
            return Target(target_id=path.as_posix(), kind=TargetKind.CONTAINER, path=path)
        return Target(target_id=path.as_posix(), kind=TargetKind.FILE, path=path)

    match = _ENDPOINT.match(raw.strip())
    if match:
        host = match.group("v6") or match.group("host")
        port = int(match.group("port"))
        if 0 < port <= 65535:
            return Target(
                target_id="%s:%d" % (host, port),
                kind=TargetKind.ENDPOINT,
                host=host,
                port=port,
            )

    return Target(target_id=raw, kind=TargetKind.UNKNOWN)


def walk_files(
    root: Path,
    suffixes: Optional[Iterable[str]] = None,
    max_bytes: int = MAX_FILE_BYTES,
) -> Iterator[Path]:
    """Yield candidate files under ``root``, skipping the usual noise.

    Streaming rather than listing: a 412-repository estate should never require
    holding every path in memory at once.
    """
    suffix_set = {s.lower() for s in suffixes} if suffixes else None
    if root.is_file():
        candidates = [root]
    else:
        candidates = None

    if candidates is not None:
        for item in candidates:
            if _acceptable(item, suffix_set, max_bytes):
                yield item
        return

    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = sorted(d for d in dirnames if d not in SKIP_DIRECTORIES)
        for name in sorted(filenames):
            item = Path(dirpath) / name
            if _acceptable(item, suffix_set, max_bytes):
                yield item


def _acceptable(item: Path, suffix_set: Optional[set], max_bytes: int) -> bool:
    if suffix_set is not None and item.suffix.lower() not in suffix_set:
        return False
    try:
        if item.stat().st_size > max_bytes:
            return False
    except OSError:
        return False
    return True


class Collector:
    """Base class for the four discovery surfaces."""

    name: str = "collector"
    surface: Surface = Surface.SOURCE

    def supports(self, target: Target) -> bool:
        raise NotImplementedError

    def collect(self, target: Target) -> Iterator[Result]:
        raise NotImplementedError

    # -- helpers for subclasses ------------------------------------------

    def error(self, target: Target, phase: str, reason: str, path: Optional[str] = None) -> CollectorError:
        return CollectorError(
            target_id=target.target_id,
            collector=self.name,
            phase=phase,
            reason=reason,
            path=path,
        )

    def safe_collect(self, target: Target) -> List[Result]:
        """Run ``collect`` with a hard guarantee that nothing escapes.

        Collectors are written to yield errors rather than raise them, but a
        genuine bug in one collector must not take down a scan of an estate, so
        this is the belt to that braces.
        """
        results: List[Result] = []
        try:
            for item in self.collect(target):
                results.append(item)
        except Exception as exc:  # noqa: BLE001 - deliberate catch-all boundary
            results.append(
                self.error(target, "collect", "%s: %s" % (type(exc).__name__, exc))
            )
        return results
