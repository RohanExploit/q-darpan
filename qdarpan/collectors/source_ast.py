"""Source-level discovery with tree-sitter.

C and C++ are the point of this collector. The existing open-source CBOM
tooling (`cbomkit/sonar-cryptography`) covers Java, Python, Go and, since
v1.7.0, C# -- but not C or C++, which is precisely what sits underneath most
Indian CII estates in the form of OpenSSL-consuming daemons.

Detection is deliberately conservative. A rule fires on a call whose name and
receiver match; arguments are read only when they are literals in the same
file. Anything unresolvable degrades to weaker evidence rather than being
guessed at, because a CBOM full of confident inventions is worse than one with
honest gaps.
"""

from __future__ import annotations

import json
import re
import threading
from pathlib import Path
from typing import Any, Dict, Iterator, List, Mapping, Optional, Tuple

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

RULES_PATH = Path(__file__).parent / "rules" / "source_rules.json"

#: File extensions per language. Headers count: a crypto call in a header is
#: still a crypto call.
LANGUAGE_SUFFIXES = {
    "c": {".c", ".h"},
    "cpp": {".cc", ".cpp", ".cxx", ".hpp", ".hh", ".hxx"},
    "java": {".java"},
    "go": {".go"},
}

#: Java Cipher transformation: ALGORITHM/MODE/PADDING.
_JCA_PADDING = {
    "nopadding": "raw",
    "pkcs5padding": "pkcs5",
    "pkcs7padding": "pkcs7",
    "pkcs1padding": "pkcs1v15",
    "oaeppadding": "oaep",
}

_MAX_SOURCE_BYTES = 4 * 1024 * 1024

#: Grammars are cached for the life of the process, not per collector instance.
#: A tree-sitter Language wraps a pointer owned by its grammar module; building
#: a fresh one for every scan churns native handles for no benefit, and the
#: parse trees that reference them outlive the call that produced them.
_LANGUAGES: Dict[str, Any] = {}
_LANGUAGE_LOCK = threading.Lock()


def _grammar(language: str):
    """Return the shared Language for a grammar, loading it once."""
    grammar = _LANGUAGES.get(language)
    if grammar is not None:
        return grammar
    with _LANGUAGE_LOCK:
        grammar = _LANGUAGES.get(language)
        if grammar is None:
            from tree_sitter import Language

            module = __import__("tree_sitter_%s" % language)
            grammar = _LANGUAGES[language] = Language(module.language())
    return grammar


def _load_rules() -> Mapping[str, Any]:
    with open(RULES_PATH, encoding="utf-8") as handle:
        return json.load(handle)


def _node_line(node) -> int:
    point = node.start_point
    row = getattr(point, "row", None)
    if row is None:
        row = point[0]
    return int(row) + 1


def _is_function(value: str) -> bool:
    """True when a rule's function name is one CycloneDX knows about."""
    try:
        CryptoFunction(value)
    except ValueError:
        return False
    return True


def _text(node) -> str:
    raw = node.text
    if isinstance(raw, bytes):
        return raw.decode("utf-8", "replace")
    return str(raw)


class SourceASTCollector(Collector):
    """Walks C, C++, Java and Go syntax trees looking for crypto calls."""

    name = "source_ast"
    surface = Surface.SOURCE

    def __init__(self, registry: Optional[Registry] = None, rules: Optional[Mapping[str, Any]] = None):
        self.registry = registry or default_registry()
        self._rules = rules or _load_rules()
        self._curve_nids = self._rules.get("openssl_curve_nids", {})
        self._include_libraries = {
            k: v for k, v in self._rules.get("include_libraries", {}).items()
            if not k.startswith("$")
        }
        # Parsers are per-thread; grammars are process-wide. See _parser().
        self._local = threading.local()
        self._index = {
            language: self._index_rules(self._rules.get(language, []))
            for language in ("c", "java", "go")
        }
        # C++ reuses the C rule pack: the OpenSSL and mbedTLS APIs are the same
        # C functions, they are simply called from C++ translation units.
        self._index["cpp"] = self._index["c"]

    # -- rule indexing ----------------------------------------------------

    @staticmethod
    def _index_rules(rules) -> Dict[str, List[dict]]:
        index: Dict[str, List[dict]] = {}
        for rule in rules:
            index.setdefault(rule["call"], []).append(rule)
        return index

    # -- parser management ------------------------------------------------

    def _parser(self, language: str):
        """Load a grammar lazily, one parser per thread.

        tree-sitter ``Parser`` objects are not thread-safe: sharing one across
        the scan's worker pool segfaults the interpreter rather than raising,
        which on a real estate would look like the tool randomly dying
        part-way through. ``Language`` objects are immutable and safe to share,
        so only the parser is thread-local.

        A missing grammar wheel degrades to "cannot scan this language" instead
        of taking down the run.
        """
        cache = getattr(self._local, "parsers", None)
        if cache is None:
            cache = self._local.parsers = {}
        if language in cache:
            return cache[language]

        try:
            from tree_sitter import Parser

            parser = Parser(_grammar(language))
        except Exception:
            parser = None

        cache[language] = parser
        return parser

    @staticmethod
    def _language_for(path: Path) -> Optional[str]:
        suffix = path.suffix.lower()
        for language, suffixes in LANGUAGE_SUFFIXES.items():
            if suffix in suffixes:
                return language
        return None

    # -- collector interface ----------------------------------------------

    def supports(self, target: Target) -> bool:
        return target.kind in (TargetKind.DIRECTORY, TargetKind.FILE)

    def collect(self, target: Target) -> Iterator[Result]:
        root = target.path
        if root is None:
            return

        all_suffixes = {s for group in LANGUAGE_SUFFIXES.values() for s in group}
        for path in walk_files(root, suffixes=all_suffixes, max_bytes=_MAX_SOURCE_BYTES):
            language = self._language_for(path)
            if language is None:
                continue
            parser = self._parser(language)
            if parser is None:
                yield self.error(
                    target, "parser", "tree-sitter grammar unavailable for %s" % language, str(path)
                )
                continue
            try:
                source = path.read_bytes()
            except OSError as exc:
                yield self.error(target, "read", str(exc), str(path))
                continue

            try:
                tree = parser.parse(source)
            except Exception as exc:  # noqa: BLE001 - grammar-level failure
                yield self.error(target, "parse", "%s: %s" % (type(exc).__name__, exc), str(path))
                continue

            for item in self._scan_tree(target, path, language, tree.root_node):
                yield item

    # -- tree walking -----------------------------------------------------

    def _scan_tree(self, target: Target, path: Path, language: str, root) -> Iterator[Result]:
        index = self._index.get(language, {})
        libraries_seen = set()

        stack = [root]
        while stack:
            node = stack.pop()
            node_type = node.type

            if node_type in ("preproc_include", "import_declaration", "import_spec"):
                library = self._library_from_include(node)
                if library and library not in libraries_seen:
                    libraries_seen.add(library)
                    finding = self._library_finding(target, path, node, library)
                    if finding is not None:
                        yield finding

            elif node_type in ("call_expression", "method_invocation"):
                for item in self._match_call(target, path, language, node, index):
                    yield item

            stack.extend(node.children)

    def _library_from_include(self, node) -> Optional[str]:
        text = _text(node)
        for needle, library in self._include_libraries.items():
            if needle in text:
                return library
        return None

    def _library_finding(self, target: Target, path: Path, node, library: str) -> Optional[CryptoFinding]:
        """Record that a crypto library is in play without naming an algorithm.

        This is the honest floor of the ladder: including ``openssl/evp.h``
        proves OpenSSL is linked and proves nothing about which algorithm is
        used, so it lands at LINKED_LIBRARY_UNPINNED and will usually be
        outweighed by a real call site once the merge runs.
        """
        return CryptoFinding(
            target_id=target.target_id,
            asset_kind=AssetKind.LIBRARY,
            name=library,
            location=Location(surface=self.surface, path=str(path), line=_node_line(node)),
            evidence=(
                Evidence(
                    tier=EvidenceTier.LINKED_LIBRARY_UNPINNED,
                    matcher_id="include.%s" % library,
                    snippet=_text(node).strip()[:120],
                ),
            ),
            collector=self.name,
            library=library,
        ).with_confidence(TIER_CONFIDENCE[EvidenceTier.LINKED_LIBRARY_UNPINNED])

    # -- call matching ----------------------------------------------------

    @staticmethod
    def _callee(node, language: str) -> Tuple[Optional[str], Optional[str]]:
        """Return ``(receiver, function_name)`` for a call node."""
        if language == "java":
            name_node = node.child_by_field_name("name")
            object_node = node.child_by_field_name("object")
            receiver = _text(object_node).split(".")[-1] if object_node is not None else None
            return receiver, _text(name_node) if name_node is not None else None

        function_node = node.child_by_field_name("function")
        if function_node is None:
            return None, None

        if function_node.type in ("selector_expression", "field_expression"):
            operand = function_node.child_by_field_name("operand") or function_node.child_by_field_name("argument")
            field = function_node.child_by_field_name("field")
            receiver = _text(operand).split(".")[-1] if operand is not None else None
            return receiver, _text(field) if field is not None else None

        if function_node.type == "qualified_identifier":
            text = _text(function_node)
            parts = text.split("::")
            return (parts[-2] if len(parts) > 1 else None), parts[-1]

        return None, _text(function_node)

    @staticmethod
    def _arguments(node) -> List[Any]:
        args_node = node.child_by_field_name("arguments")
        if args_node is None:
            return []
        return [child for child in args_node.named_children]

    def _match_call(
        self, target: Target, path: Path, language: str, node, index: Mapping[str, List[dict]]
    ) -> Iterator[Result]:
        receiver, function_name = self._callee(node, language)
        if not function_name:
            return

        for rule in index.get(function_name, []):
            expected_receiver = rule.get("receiver")
            if expected_receiver and receiver != expected_receiver:
                continue
            finding = self._build_finding(target, path, node, rule)
            if finding is not None:
                yield finding

    def _build_finding(self, target: Target, path: Path, node, rule: Mapping[str, Any]) -> Optional[CryptoFinding]:
        args = self._arguments(node)
        parameters: Dict[str, Any] = dict(rule.get("parameters") or {})
        algorithm = rule.get("algorithm")
        tier = EvidenceTier.DIRECT_API_CALL

        if "arg_jca_spec" in rule:
            spec = self._literal_string(args, rule["arg_jca_spec"])
            if spec is None:
                if rule.get("skip_unresolved"):
                    return None
                tier = EvidenceTier.LINKED_LIBRARY_UNPINNED
                algorithm = algorithm or rule.get("library")
            else:
                algorithm, extra = self._parse_jca_spec(spec)
                parameters.update(extra)

        elif "arg_algorithm" in rule:
            spec = self._literal_string(args, rule["arg_algorithm"])
            if spec is None:
                if rule.get("skip_unresolved"):
                    return None
                tier = EvidenceTier.LINKED_LIBRARY_UNPINNED
                algorithm = algorithm or rule.get("library")
            else:
                algorithm = spec

        if "arg_key_size" in rule:
            size = self._literal_int(args, rule["arg_key_size"])
            if size is not None:
                parameters["key_size"] = size
            else:
                # The call is real, the key size is not statically known.
                tier = EvidenceTier.LINKED_LIBRARY_PINNED

        if "arg_curve_nid" in rule:
            nid = self._literal_identifier(args, rule["arg_curve_nid"])
            curve = self._curve_nids.get(nid) if nid else None
            if curve:
                parameters["curve"] = curve
            else:
                tier = EvidenceTier.LINKED_LIBRARY_PINNED

        if not algorithm:
            return None

        try:
            canonical = self.registry.canonicalise(algorithm, parameters)
        except UnknownAlgorithm:
            # An unrecognised algorithm string is still worth reporting -- it
            # may be a registry gap -- but only as a weak literal sighting.
            return CryptoFinding(
                target_id=target.target_id,
                asset_kind=AssetKind.ALGORITHM,
                name=str(algorithm),
                location=Location(surface=self.surface, path=str(path), line=_node_line(node)),
                evidence=(
                    Evidence(
                        tier=EvidenceTier.STRING_LITERAL,
                        matcher_id=rule["id"],
                        snippet=_text(node).strip()[:160],
                        detail={"unresolved": True},
                    ),
                ),
                collector=self.name,
                parameters=parameters,
                library=rule.get("library"),
            ).with_confidence(0.40)

        functions = frozenset(
            CryptoFunction(fn) for fn in rule.get("functions", []) if _is_function(fn)
        )
        evidence = (
            Evidence(
                tier=tier,
                matcher_id=rule["id"],
                snippet=_text(node).strip()[:160],
            ),
        )
        return CryptoFinding(
            target_id=target.target_id,
            asset_kind=AssetKind.ALGORITHM,
            name=canonical.name,
            location=Location(surface=self.surface, path=str(path), line=_node_line(node)),
            evidence=evidence,
            collector=self.name,
            primitive=canonical.primitive,
            parameters=canonical.parameters,
            oid=canonical.oid,
            functions=functions,
            library=rule.get("library"),
        ).with_confidence(evidence[0].base_confidence)

    # -- literal extraction ------------------------------------------------

    @staticmethod
    def _literal_string(args: List[Any], index: int) -> Optional[str]:
        if index >= len(args):
            return None
        node = args[index]
        if "string" not in node.type:
            return None
        text = _text(node).strip()
        if len(text) >= 2 and text[0] in "\"'" and text[-1] == text[0]:
            return text[1:-1]
        return text

    @staticmethod
    def _literal_int(args: List[Any], index: int) -> Optional[int]:
        if index >= len(args):
            return None
        text = _text(args[index]).strip()
        match = re.fullmatch(r"(\d+)[uUlL]*", text)
        if match:
            return int(match.group(1))
        return None

    @staticmethod
    def _literal_identifier(args: List[Any], index: int) -> Optional[str]:
        if index >= len(args):
            return None
        text = _text(args[index]).strip()
        return text if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", text) else None

    @staticmethod
    def _parse_jca_spec(spec: str) -> Tuple[str, Dict[str, Any]]:
        """Split a JCA transformation such as ``AES/GCM/NoPadding``.

        A bare algorithm name is legal too -- ``Cipher.getInstance("RSA")`` --
        in which case there is no mode or padding to record.
        """
        parts = [p.strip() for p in spec.split("/")]
        algorithm = parts[0]
        extra: Dict[str, Any] = {}
        if len(parts) > 1 and parts[1]:
            extra["mode"] = parts[1].lower()
        if len(parts) > 2 and parts[2]:
            padding = parts[2].lower()
            extra["padding"] = _JCA_PADDING.get(padding, "oaep" if padding.startswith("oaep") else "other")
        return algorithm, extra
