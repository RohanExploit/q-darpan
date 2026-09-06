"""Emission of a CycloneDX 1.7 Cryptographic Bill of Materials.

CycloneDX v1.7 is ECMA-424 2nd edition (December 2025); v1.6 was the 1st
edition. Emitting 1.7 is what makes the output something an auditor can reload
into any conformant tool rather than a bespoke report.

Confidence and evidence have no native home in the CycloneDX crypto model, so
they ride as namespaced ``qdarpan:*`` properties. The JSONL journal remains the
authoritative evidence record; the CBOM is the interchange format.
"""

from __future__ import annotations

import hashlib
import json
import uuid
from datetime import datetime, timezone
from typing import Iterable, List, Optional, Sequence

from cyclonedx.model import Property
from cyclonedx.model.bom import Bom, BomMetaData
from cyclonedx.model.component import Component, ComponentType
from cyclonedx.model.crypto import (
    AlgorithmProperties,
    CryptoAssetType,
    CryptoFunction as CdxCryptoFunction,
    CryptoMode,
    CryptoPadding,
    CryptoPrimitive,
    CryptoProperties,
    ProtocolProperties,
    ProtocolPropertiesType,
    RelatedCryptoMaterialProperties,
    RelatedCryptoMaterialType,
)
from cyclonedx.model.tool import Tool
from cyclonedx.output import make_outputter
from cyclonedx.schema import OutputFormat, SchemaVersion

from .canonical import Registry, default_registry
from .ir import AssetKind, DEFAULT_CONFIDENCE_FLOOR, Primitive
from .journal import TOOL_NAME, TOOL_VERSION
from .normalise import MergedFinding

#: Fixed timestamp for reproducible builds. A CBOM that differs only in its
#: timestamp is noise in a quarter-over-quarter diff.
EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)

_PROTOCOL_TYPES = {
    "TLS": ProtocolPropertiesType.TLS,
    "SSH": ProtocolPropertiesType.SSH,
    "IPSEC": ProtocolPropertiesType.IPSEC,
    "IKE": ProtocolPropertiesType.IKE,
    "QUIC": ProtocolPropertiesType.QUIC,
    "DTLS": ProtocolPropertiesType.DTLS,
}


def _enum_or_none(enum_cls, value):
    """Map a string onto a CycloneDX enum, tolerating absence.

    Vocabulary mismatches degrade to ``None`` rather than raising: a finding
    with an unrepresentable mode is still worth emitting without the mode.
    """
    if value is None:
        return None
    try:
        return enum_cls(str(value).lower())
    except ValueError:
        return None


def _primitive(primitive: Primitive) -> Optional[CryptoPrimitive]:
    return _enum_or_none(CryptoPrimitive, primitive.value)


def _properties(item: MergedFinding, registry: Registry) -> List[Property]:
    """The ``qdarpan:*`` property bag.

    Everything here is provenance the CycloneDX schema has no field for, and
    all of it is what a reviewer needs to decide whether to trust a finding.
    """
    finding = item.finding
    props = [
        Property(name="qdarpan:confidence", value="%.4f" % finding.confidence),
        Property(name="qdarpan:collectors", value=",".join(item.collectors)),
        Property(name="qdarpan:surfaces", value=",".join(s.value for s in item.surfaces)),
        Property(name="qdarpan:corroborated", value=str(item.corroborated).lower()),
        Property(name="qdarpan:target", value=finding.target_id),
        Property(
            name="qdarpan:evidence-tiers",
            value=",".join(sorted({e.tier.value for e in finding.evidence})),
        ),
        Property(
            name="qdarpan:matchers",
            value=",".join(sorted({e.matcher_id for e in finding.evidence})),
        ),
    ]
    for index, location in enumerate(item.locations):
        props.append(Property(name="qdarpan:location.%d" % index, value=location.describe()))

    family = registry.resolve_family(finding.name)
    if family:
        entry = registry.entry(family)
        props.append(Property(name="qdarpan:family", value=family))
        props.append(
            Property(name="qdarpan:quantum-status", value=entry.get("quantum_status", "unknown"))
        )
        props.append(
            Property(
                name="qdarpan:classical-status", value=entry.get("classical_status", "unknown")
            )
        )
    return props


def _algorithm_properties(item: MergedFinding, registry: Registry) -> AlgorithmProperties:
    finding = item.finding
    params = finding.parameters
    canonical = None
    try:
        canonical = registry.canonicalise(finding.name, params)
    except Exception:
        canonical = None

    parameter_set = None
    if params.get("key_size") is not None:
        parameter_set = str(params["key_size"])

    return AlgorithmProperties(
        primitive=_primitive(finding.primitive),
        parameter_set_identifier=parameter_set,
        curve=params.get("curve"),
        mode=_enum_or_none(CryptoMode, params.get("mode")),
        padding=_enum_or_none(CryptoPadding, params.get("padding")),
        crypto_functions=[
            fn
            for fn in (_enum_or_none(CdxCryptoFunction, f.value) for f in finding.functions)
            if fn is not None
        ],
        classical_security_level=canonical.security_bits if canonical else None,
        nist_quantum_security_level=canonical.nist_level if canonical else None,
    )


def _crypto_properties(item: MergedFinding, registry: Registry) -> Optional[CryptoProperties]:
    finding = item.finding
    kind = finding.asset_kind

    if kind is AssetKind.ALGORITHM:
        return CryptoProperties(
            asset_type=CryptoAssetType.ALGORITHM,
            algorithm_properties=_algorithm_properties(item, registry),
            oid=finding.oid,
        )

    if kind is AssetKind.PROTOCOL:
        family = (finding.parameters.get("protocol") or finding.name).upper()
        protocol_type = next(
            (value for key, value in _PROTOCOL_TYPES.items() if family.startswith(key)),
            ProtocolPropertiesType.OTHER,
        )
        return CryptoProperties(
            asset_type=CryptoAssetType.PROTOCOL,
            protocol_properties=ProtocolProperties(
                type=protocol_type,
                version=str(finding.parameters.get("version") or ""),
            ),
            oid=finding.oid,
        )

    if kind is AssetKind.RELATED_MATERIAL:
        material_type = _enum_or_none(
            RelatedCryptoMaterialType, finding.parameters.get("material_type")
        )
        size = finding.parameters.get("key_size")
        return CryptoProperties(
            asset_type=CryptoAssetType.RELATED_CRYPTO_MATERIAL,
            related_crypto_material_properties=RelatedCryptoMaterialProperties(
                type=material_type or RelatedCryptoMaterialType.KEY,
                size=int(size) if size is not None else None,
            ),
            oid=finding.oid,
        )

    if kind is AssetKind.CERTIFICATE:
        # Certificate detail is carried in properties rather than
        # CertificateProperties: the latter's fields expect BomRef links to
        # separately emitted key and algorithm components, which is a Phase 3
        # refinement rather than something to fake here.
        return CryptoProperties(asset_type=CryptoAssetType.CERTIFICATE, oid=finding.oid)

    return None


def _component(item: MergedFinding, registry: Registry) -> Component:
    finding = item.finding
    is_library = finding.asset_kind is AssetKind.LIBRARY
    return Component(
        name=finding.name,
        type=ComponentType.LIBRARY if is_library else ComponentType.CRYPTOGRAPHIC_ASSET,
        bom_ref=finding.bom_ref(),
        version=finding.parameters.get("library_version"),
        description=finding.location.describe(),
        properties=_properties(item, registry),
        crypto_properties=None if is_library else _crypto_properties(item, registry),
    )


def build_bom(
    merged: Sequence[MergedFinding],
    *,
    reproducible: bool = False,
    confidence_floor: float = DEFAULT_CONFIDENCE_FLOOR,
    include_low_confidence: bool = False,
    registry: Optional[Registry] = None,
    timestamp: Optional[datetime] = None,
) -> Bom:
    """Assemble a CycloneDX 1.7 BOM from merged findings.

    Low-confidence findings are excluded by default. They stay in the journal,
    so nothing is lost -- but shipping a filename-based guess inside a CBOM an
    auditor will read is worse than omitting it.
    """
    registry = registry or default_registry()

    kept = [
        item
        for item in merged
        if include_low_confidence or item.confidence >= confidence_floor
    ]
    kept.sort(key=lambda item: item.finding.bom_ref())

    components = [_component(item, registry) for item in kept]

    metadata = BomMetaData(
        tools=[Tool(vendor="Q-DARPAN", name=TOOL_NAME, version=TOOL_VERSION)],
        timestamp=EPOCH if reproducible else (timestamp or datetime.now(timezone.utc)),
    )

    bom = Bom(components=components, metadata=metadata)
    if reproducible:
        # Derive the serial number from the content so that two scans of
        # unchanged inputs produce byte-identical documents.
        digest = hashlib.sha256(
            "".join(item.finding.bom_ref() for item in kept).encode("utf-8")
        ).digest()
        bom.serial_number = uuid.UUID(bytes=digest[:16], version=4)
    return bom


def to_json(bom: Bom, *, indent: int = 2) -> str:
    outputter = make_outputter(bom, OutputFormat.JSON, SchemaVersion.V1_7)
    return outputter.output_as_string(indent=indent)


def emit(
    merged: Sequence[MergedFinding],
    **kwargs,
) -> str:
    """Convenience wrapper: merged findings in, CBOM JSON text out."""
    return to_json(build_bom(merged, **kwargs))


def load_cbom(path) -> dict:
    """Read a CBOM back for diffing. Kept here so the format lives in one place."""
    with open(path, encoding="utf-8") as handle:
        return json.load(handle)


def crypto_components(document: dict) -> Iterable[dict]:
    """Yield the cryptographic-asset components of a loaded CBOM."""
    for component in document.get("components", []):
        if component.get("type") in ("cryptographic-asset", "library"):
            yield component
