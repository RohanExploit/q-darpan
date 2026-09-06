"""Container image discovery without a Docker daemon.

A CII enclave does not run a registry client and often does not run Docker at
all -- images arrive as ``docker save`` tarballs on removable media. So this
collector reads three shapes directly:

* an OCI image layout directory (``oci-layout`` / ``index.json`` / ``blobs/``)
* a ``docker save`` tarball
* an already-extracted rootfs directory

Layer digests are carried into every finding, so an auditor can see which layer
introduced a weak algorithm rather than only that the image contains one.
"""

from __future__ import annotations

import json
import tarfile
import tempfile
from pathlib import Path
from typing import Dict, Iterator, List, Optional, Set, Tuple

from ..canonical import Registry, default_registry
from ..ir import (
    TIER_CONFIDENCE,
    AssetKind,
    CryptoFinding,
    Evidence,
    EvidenceTier,
    Location,
    Surface,
)
from .base import Collector, Result, Target, TargetKind
from .elf import ELF_MAGIC, ELFCollector

#: Package databases worth reading. Each one attributes a crypto library to a
#: package and a version, which is what turns "libcrypto is present" into
#: "openssl 3.0.2 is present".
_PACKAGE_DBS = {
    "var/lib/dpkg/status": "dpkg",
    "lib/apk/db/installed": "apk",
}

_CRYPTO_PACKAGE_PREFIXES = (
    "openssl", "libssl", "libcrypto", "libgcrypt", "gnutls", "libgnutls",
    "nss", "libnss", "libsodium", "mbedtls", "wolfssl", "ca-certificates",
)

#: Files inside a layer larger than this are skipped. Layers routinely carry
#: model weights and datasets that are not going to contain an S-box.
_MAX_MEMBER_BYTES = 64 * 1024 * 1024


class ContainerCollector(Collector):
    """Walks image layers and runs binary analysis over what it finds."""

    name = "container"
    surface = Surface.CONTAINER

    def __init__(self, registry: Optional[Registry] = None):
        self.registry = registry or default_registry()
        self._elf = ELFCollector(registry=self.registry)

    def supports(self, target: Target) -> bool:
        return target.kind == TargetKind.CONTAINER

    def collect(self, target: Target) -> Iterator[Result]:
        path = target.path
        if path is None:
            return

        if path.is_dir():
            if (path / "oci-layout").exists() or (path / "index.json").exists():
                yield from self._scan_oci_layout(target, path)
            else:
                yield from self._scan_rootfs(target, path)
            return

        yield from self._scan_tarball(target, path)

    # -- docker save tarball ----------------------------------------------

    def _scan_tarball(self, target: Target, path: Path) -> Iterator[Result]:
        try:
            archive = tarfile.open(path, "r:*")
        except (tarfile.TarError, OSError) as exc:
            yield self.error(target, "open", "%s: %s" % (type(exc).__name__, exc), str(path))
            return

        with archive:
            layer_names = self._layer_names(archive)
            if not layer_names:
                # Not an image archive after all -- treat it as a plain tarball
                # of files rather than reporting nothing.
                yield from self._scan_members(target, archive, layer_digest=None)
                return

            for layer_name in layer_names:
                try:
                    member = archive.getmember(layer_name)
                except KeyError:
                    yield self.error(target, "layer", "layer not present in archive", layer_name)
                    continue
                stream = archive.extractfile(member)
                if stream is None:
                    continue
                digest = self._digest_from_name(layer_name)
                try:
                    with tarfile.open(fileobj=stream, mode="r|*") as layer:
                        yield from self._scan_members(target, layer, layer_digest=digest)
                except tarfile.TarError as exc:
                    yield self.error(target, "layer", str(exc), layer_name)

    @staticmethod
    def _layer_names(archive: tarfile.TarFile) -> List[str]:
        """Read the layer list from a docker-save or OCI manifest."""
        names = set(archive.getnames())

        if "manifest.json" in names:
            try:
                handle = archive.extractfile("manifest.json")
                if handle is not None:
                    manifest = json.loads(handle.read().decode("utf-8"))
                    layers: List[str] = []
                    for entry in manifest:
                        layers.extend(entry.get("Layers", []))
                    if layers:
                        return layers
            except (json.JSONDecodeError, UnicodeDecodeError, KeyError):
                pass

        # OCI layout inside a tarball: every blob is a candidate layer.
        blobs = sorted(n for n in names if n.startswith("blobs/sha256/"))
        return blobs

    @staticmethod
    def _digest_from_name(name: str) -> Optional[str]:
        parts = name.split("/")
        for part in parts:
            if len(part) == 64 and all(c in "0123456789abcdef" for c in part):
                return "sha256:" + part
        return parts[0] if parts else None

    def _scan_members(
        self, target: Target, archive: tarfile.TarFile, layer_digest: Optional[str]
    ) -> Iterator[Result]:
        for member in archive:
            if not member.isfile() or member.size > _MAX_MEMBER_BYTES:
                continue

            normalised = member.name.lstrip("./")
            db_kind = _PACKAGE_DBS.get(normalised)
            if db_kind:
                stream = archive.extractfile(member)
                if stream is not None:
                    text = stream.read().decode("utf-8", "replace")
                    yield from self._packages(target, text, db_kind, layer_digest)
                continue

            stream = archive.extractfile(member)
            if stream is None:
                continue
            head = stream.read(4)
            if head != ELF_MAGIC:
                continue
            rest = stream.read()
            yield from self._scan_extracted(target, head + rest, member.name, layer_digest)

    def _scan_extracted(
        self, target: Target, blob: bytes, display_path: str, layer_digest: Optional[str]
    ) -> Iterator[Result]:
        """Materialise one binary and hand it to the ELF collector.

        pyelftools needs a seekable file, and a tar member stream is not, so the
        blob lands in a temporary file that is deleted immediately afterwards.
        """
        with tempfile.NamedTemporaryFile(delete=False, suffix=".elf") as handle:
            handle.write(blob)
            temp_path = Path(handle.name)
        try:
            for item in self._elf.scan_binary(
                target, temp_path, layer_digest=layer_digest, display_path=display_path
            ):
                yield self._retag(item)
        finally:
            try:
                temp_path.unlink()
            except OSError:
                pass

    def _retag(self, item: Result) -> Result:
        """Re-attribute an ELF finding to the container surface.

        The evidence is unchanged -- it really was an ELF constant -- but the
        surface is what the operator scanned, and reporting it as ``elf`` would
        make a container scan look like a filesystem scan.
        """
        if isinstance(item, CryptoFinding):
            from dataclasses import replace

            return replace(
                item,
                collector=self.name,
                location=replace(item.location, surface=self.surface),
            )
        return item

    # -- OCI layout directory ---------------------------------------------

    def _scan_oci_layout(self, target: Target, root: Path) -> Iterator[Result]:
        blobs = root / "blobs" / "sha256"
        if not blobs.is_dir():
            yield self.error(target, "layout", "no blobs/sha256 directory", str(root))
            return

        for blob in sorted(blobs.iterdir()):
            if not blob.is_file():
                continue
            digest = "sha256:" + blob.name
            try:
                with tarfile.open(blob, "r:*") as layer:
                    yield from self._scan_members(target, layer, layer_digest=digest)
            except tarfile.TarError:
                # Config and manifest blobs are JSON, not tar. Not an error.
                continue

    # -- extracted rootfs --------------------------------------------------

    def _scan_rootfs(self, target: Target, root: Path) -> Iterator[Result]:
        for relative, kind in _PACKAGE_DBS.items():
            db_path = root / relative
            if db_path.is_file():
                try:
                    text = db_path.read_text(encoding="utf-8", errors="replace")
                except OSError:
                    continue
                yield from self._packages(target, text, kind, layer_digest=None)

        for item in self._elf.collect(target):
            yield self._retag(item)

    # -- package metadata --------------------------------------------------

    def _packages(
        self, target: Target, text: str, kind: str, layer_digest: Optional[str]
    ) -> Iterator[Result]:
        """Extract crypto-relevant packages and versions from a package DB.

        dpkg and apk both use RFC822-ish stanzas, so one parser covers both with
        different field letters.
        """
        name_field, version_field = ("Package", "Version") if kind == "dpkg" else ("P", "V")
        seen: Set[Tuple[str, str]] = set()

        for stanza in text.split("\n\n"):
            fields: Dict[str, str] = {}
            for line in stanza.splitlines():
                if ":" in line and not line.startswith((" ", "\t")):
                    key, _, value = line.partition(":")
                    fields[key.strip()] = value.strip()
            name = fields.get(name_field)
            version = fields.get(version_field)
            if not name:
                continue
            lowered = name.lower()
            if not any(lowered.startswith(prefix) for prefix in _CRYPTO_PACKAGE_PREFIXES):
                continue
            key = (name, version or "")
            if key in seen:
                continue
            seen.add(key)

            yield CryptoFinding(
                target_id=target.target_id,
                asset_kind=AssetKind.LIBRARY,
                name=name,
                location=Location(
                    surface=self.surface,
                    path="%s package database" % kind,
                    layer_digest=layer_digest,
                ),
                evidence=(
                    Evidence(
                        tier=EvidenceTier.FILENAME_METADATA,
                        matcher_id="package.%s" % kind,
                        snippet="%s %s" % (name, version or "?"),
                        detail={"package_manager": kind},
                    ),
                ),
                collector=self.name,
                library=name,
                parameters={"library_version": version} if version else {},
            ).with_confidence(TIER_CONFIDENCE[EvidenceTier.FILENAME_METADATA])
