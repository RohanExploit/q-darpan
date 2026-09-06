"""Discovery collectors: one module per surface."""

from .base import Collector, Result, Target, TargetKind, classify
from .container import ContainerCollector
from .elf import ELFCollector
from .source_ast import SourceASTCollector
from .tls import TLSCollector

#: Registry of every collector, keyed by the ``--surface`` name a user types.
COLLECTOR_TYPES = {
    "source": SourceASTCollector,
    "elf": ELFCollector,
    "container": ContainerCollector,
    "tls": TLSCollector,
}

ALL_SURFACES = tuple(COLLECTOR_TYPES)

#: Surfaces that touch the network. Excluded under ``--offline``.
NETWORK_SURFACES = frozenset({"tls"})

__all__ = [
    "ALL_SURFACES",
    "COLLECTOR_TYPES",
    "Collector",
    "ContainerCollector",
    "ELFCollector",
    "NETWORK_SURFACES",
    "Result",
    "SourceASTCollector",
    "TLSCollector",
    "Target",
    "TargetKind",
    "classify",
]
