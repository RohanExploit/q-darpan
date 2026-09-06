"""Q-DARPAN: enterprise cryptographic discovery and quantum risk analysis.

Four collectors, one intermediate representation, a CycloneDX 1.7 CBOM, a Mosca
risk model evaluated across three CRQC scenarios, and a FIPS 203/204/205
migration queue. No network egress, no agents, no GPU.
"""

from .ir import (
    AssetKind,
    CollectorError,
    CryptoFinding,
    CryptoFunction,
    Evidence,
    EvidenceTier,
    Location,
    Primitive,
    Surface,
)

__version__ = "0.1.0"

__all__ = [
    "AssetKind",
    "CollectorError",
    "CryptoFinding",
    "CryptoFunction",
    "Evidence",
    "EvidenceTier",
    "Location",
    "Primitive",
    "Surface",
    "__version__",
]
