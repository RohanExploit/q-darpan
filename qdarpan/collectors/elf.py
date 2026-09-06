"""Binary discovery for ELF objects.

Three questions, in descending order of certainty:

1. What crypto libraries does this binary link against? (``DT_NEEDED``)
2. Which crypto symbols does it import or export? (``.dynsym`` / ``.symtab``)
3. Which crypto constants are baked into it? (``.rodata`` and friends)

The third exists for stripped and statically linked binaries, where the first
two give nothing at all. Finding the AES S-box in ``.rodata`` does not tell you
the key size, so those findings sit at CRYPTO_CONSTANT rather than pretending
to be a call site -- but "AES is in this binary" is exactly the fact an
inventory is missing today.
"""

from __future__ import annotations

import json
import mmap
from pathlib import Path
from typing import Any, Dict, Iterator, List, Mapping, Optional, Set

from ..canonical import Registry, UnknownAlgorithm, default_registry
from ..ir import (
    TIER_CONFIDENCE,
    AssetKind,
    CryptoFinding,
    CryptoFunction,
    Evidence,
    EvidenceTier,
    Location,
    Surface,
)
from .base import Collector, Result, Target, TargetKind, walk_files
from .source_ast import RULES_PATH, _is_function

CONSTANTS_PATH = Path(__file__).parent / "rules" / "binary_constants.json"

ELF_MAGIC = b"\x7fELF"

#: Sections worth searching for constants. Constants live in read-only data;
#: scanning .text as well would multiply runtime for very little yield.
_CONSTANT_SECTIONS = (".rodata", ".data.rel.ro", ".rdata", ".data")

_MAX_BINARY_BYTES = 512 * 1024 * 1024


def _load_json(path: Path) -> Mapping[str, Any]:
    with open(path, encoding="utf-8") as handle:
        return json.load(handle)


def is_elf(path: Path) -> bool:
    """Cheap magic-number test so we do not hand every file to pyelftools."""
    try:
        with open(path, "rb") as handle:
            return handle.read(4) == ELF_MAGIC
    except OSError:
        return False


class ELFCollector(Collector):
    """Reads linkage, symbols and embedded constants out of ELF binaries."""

    name = "elf"
    surface = Surface.ELF

    def __init__(self, registry: Optional[Registry] = None):
        self.registry = registry or default_registry()
        constants = _load_json(CONSTANTS_PATH)
        self._constants = [c for c in constants["constants"] if not str(c["id"]).startswith("$")]
        self._needed = {
            k: v for k, v in constants["needed_libraries"].items() if not k.startswith("$")
        }
        # Symbol names reuse the C rule pack. That is not a shortcut: the
        # symbol a stripped-but-dynamic binary imports is literally the
        # function the source called, so one rule id describes both sightings
        # and the normaliser can corroborate them across surfaces.
        source_rules = _load_json(RULES_PATH)
        self._symbol_rules: Dict[str, dict] = {}
        for rule in source_rules.get("c", []):
            self._symbol_rules.setdefault(rule["call"], rule)

    def supports(self, target: Target) -> bool:
        return target.kind in (TargetKind.DIRECTORY, TargetKind.FILE)

    def collect(self, target: Target) -> Iterator[Result]:
        root = target.path
        if root is None:
            return
        for path in walk_files(root, max_bytes=_MAX_BINARY_BYTES):
            if not is_elf(path):
                continue
            for item in self.scan_binary(target, path):
                yield item

    # -- single binary ----------------------------------------------------

    def scan_binary(
        self,
        target: Target,
        path: Path,
        layer_digest: Optional[str] = None,
        display_path: Optional[str] = None,
    ) -> Iterator[Result]:
        """Scan one ELF file.

        Exposed separately so the container collector can reuse it on files
        extracted from image layers without duplicating any of this logic.
        """
        try:
            from elftools.elf.elffile import ELFFile
        except ImportError:
            yield self.error(target, "import", "pyelftools is not installed", str(path))
            return

        shown = display_path or str(path)
        try:
            with open(path, "rb") as handle:
                elf = ELFFile(handle)
                for item in self._needed_libraries(target, elf, shown, layer_digest):
                    yield item
                for item in self._symbols(target, elf, shown, layer_digest):
                    yield item
                for item in self._constants_in(target, elf, handle, shown, layer_digest):
                    yield item
        except Exception as exc:  # noqa: BLE001 - malformed binaries are expected
            yield self.error(
                target, "elf", "%s: %s" % (type(exc).__name__, exc), shown
            )

    # -- DT_NEEDED --------------------------------------------------------

    def _needed_libraries(self, target, elf, shown, layer_digest) -> Iterator[Result]:
        dynamic = elf.get_section_by_name(".dynamic")
        if dynamic is None:
            return
        for tag in dynamic.iter_tags():
            if tag.entry.d_tag != "DT_NEEDED":
                continue
            soname = str(tag.needed)
            library = self._match_library(soname)
            if not library:
                continue
            yield CryptoFinding(
                target_id=target.target_id,
                asset_kind=AssetKind.LIBRARY,
                name=library,
                location=Location(
                    surface=self.surface, path=shown, layer_digest=layer_digest
                ),
                evidence=(
                    Evidence(
                        tier=EvidenceTier.LINKED_LIBRARY_UNPINNED,
                        matcher_id="dt_needed.%s" % library,
                        snippet=soname,
                        detail={"soname": soname},
                    ),
                ),
                collector=self.name,
                library=library,
                parameters={"soname": soname},
            ).with_confidence(TIER_CONFIDENCE[EvidenceTier.LINKED_LIBRARY_UNPINNED])

    def _match_library(self, soname: str) -> Optional[str]:
        lowered = soname.lower()
        for prefix, library in self._needed.items():
            if lowered.startswith(prefix):
                return library
        return None

    # -- symbols ----------------------------------------------------------

    def _symbols(self, target, elf, shown, layer_digest) -> Iterator[Result]:
        from elftools.elf.sections import SymbolTableSection

        seen: Set[str] = set()
        for section in elf.iter_sections():
            if not isinstance(section, SymbolTableSection):
                continue
            for symbol in section.iter_symbols():
                name = symbol.name
                if not name or name in seen:
                    continue
                rule = self._symbol_rules.get(name)
                if rule is None:
                    continue
                seen.add(name)
                finding = self._finding_from_rule(
                    target, rule, shown, layer_digest,
                    tier=EvidenceTier.LINKED_LIBRARY_PINNED,
                    matcher_id=rule["id"],
                    snippet=name,
                )
                if finding is not None:
                    yield finding

    # -- constants --------------------------------------------------------

    def _constants_in(self, target, elf, handle, shown, layer_digest) -> Iterator[Result]:
        """Search read-only sections for known crypto tables.

        Sections are read one at a time rather than mapping the whole file, so
        a 400 MB static binary does not become a 400 MB allocation.
        """
        found: Set[str] = set()
        for section_name in _CONSTANT_SECTIONS:
            section = elf.get_section_by_name(section_name)
            if section is None:
                continue
            try:
                data = section.data()
            except Exception:  # noqa: BLE001 - truncated section
                continue
            for constant in self._constants:
                if constant["id"] in found:
                    continue
                needle = bytes.fromhex(constant["hex"])
                offset = data.find(needle)
                if offset < 0:
                    continue
                found.add(constant["id"])
                finding = self._finding_from_constant(
                    target, constant, shown, layer_digest,
                    offset=section["sh_addr"] + offset if section["sh_addr"] else offset,
                    section=section_name,
                )
                if finding is not None:
                    yield finding

    # -- finding construction ----------------------------------------------

    def _finding_from_rule(
        self, target, rule, shown, layer_digest, *, tier, matcher_id, snippet
    ) -> Optional[CryptoFinding]:
        algorithm = rule.get("algorithm")
        if not algorithm:
            return None
        parameters = dict(rule.get("parameters") or {})
        try:
            canonical = self.registry.canonicalise(algorithm, parameters)
        except UnknownAlgorithm:
            return None
        return CryptoFinding(
            target_id=target.target_id,
            asset_kind=AssetKind.ALGORITHM,
            name=canonical.name,
            location=Location(surface=self.surface, path=shown, layer_digest=layer_digest),
            evidence=(Evidence(tier=tier, matcher_id=matcher_id, snippet=snippet),),
            collector=self.name,
            primitive=canonical.primitive,
            parameters=canonical.parameters,
            oid=canonical.oid,
            functions=frozenset(
                CryptoFunction(fn) for fn in rule.get("functions", []) if _is_function(fn)
            ),
            library=rule.get("library"),
        ).with_confidence(TIER_CONFIDENCE[tier])

    def _finding_from_constant(
        self, target, constant, shown, layer_digest, *, offset, section
    ) -> Optional[CryptoFinding]:
        parameters = dict(constant.get("parameters") or {})
        try:
            canonical = self.registry.canonicalise(constant["algorithm"], parameters)
        except UnknownAlgorithm:
            return None
        return CryptoFinding(
            target_id=target.target_id,
            asset_kind=AssetKind.ALGORITHM,
            name=canonical.name,
            location=Location(
                surface=self.surface, path=shown, offset=int(offset), layer_digest=layer_digest
            ),
            evidence=(
                Evidence(
                    tier=EvidenceTier.CRYPTO_CONSTANT,
                    matcher_id=constant["id"],
                    snippet=constant["description"],
                    detail={"section": section, "hex": constant["hex"]},
                ),
            ),
            collector=self.name,
            primitive=canonical.primitive,
            parameters=canonical.parameters,
            oid=canonical.oid,
            functions=frozenset(
                CryptoFunction(fn) for fn in constant.get("functions", []) if _is_function(fn)
            ),
        ).with_confidence(TIER_CONFIDENCE[EvidenceTier.CRYPTO_CONSTANT])
