"""Cross-surface merging and the confidence arithmetic that depends on it."""

from __future__ import annotations

import pytest

from qdarpan.ir import (
    AssetKind,
    CryptoFinding,
    Evidence,
    EvidenceTier,
    Location,
    Primitive,
    Surface,
    combine_confidence,
)
from qdarpan.normalise import blast_radius, merge


def finding(
    *,
    target="repo-a",
    name="AES-256-GCM",
    surface=Surface.SOURCE,
    tier=EvidenceTier.DIRECT_API_CALL,
    matcher="rule.a",
    parameters=None,
    collector="source_ast",
    path="a.c",
):
    evidence = (Evidence(tier=tier, matcher_id=matcher),)
    return CryptoFinding(
        target_id=target,
        asset_kind=AssetKind.ALGORITHM,
        name=name,
        location=Location(surface=surface, path=path),
        evidence=evidence,
        collector=collector,
        primitive=Primitive.BLOCK_CIPHER,
        parameters=parameters or {"key_size": 256, "mode": "gcm"},
    ).with_confidence(evidence[0].base_confidence)


def test_same_asset_in_one_target_merges_across_surfaces():
    """Source and binary sightings of one algorithm are one fact, two witnesses."""
    merged = merge(
        [
            finding(surface=Surface.SOURCE, tier=EvidenceTier.DIRECT_API_CALL),
            finding(
                surface=Surface.ELF,
                tier=EvidenceTier.CRYPTO_CONSTANT,
                matcher="const.aes.sbox",
                collector="elf",
                path="bin/daemon",
            ),
        ]
    )
    assert len(merged) == 1
    item = merged[0]
    assert item.corroborated
    assert set(item.surfaces) == {Surface.SOURCE, Surface.ELF}
    assert set(item.collectors) == {"source_ast", "elf"}
    assert len(item.locations) == 2


def test_same_asset_in_two_targets_stays_separate():
    """target_id is part of the identity: two repos are two findings."""
    merged = merge([finding(target="repo-a"), finding(target="repo-b")])
    assert len(merged) == 2


def test_different_key_sizes_do_not_merge():
    merged = merge(
        [
            finding(name="AES-128-GCM", parameters={"key_size": 128, "mode": "gcm"}),
            finding(name="AES-256-GCM", parameters={"key_size": 256, "mode": "gcm"}),
        ]
    )
    assert len(merged) == 2


def test_noisy_or_raises_confidence_on_corroboration():
    """0.95 and 0.70 combine to 0.985, not to either input and not to 1.0."""
    merged = merge(
        [
            finding(tier=EvidenceTier.DIRECT_API_CALL, matcher="rule.a"),
            finding(
                surface=Surface.ELF,
                tier=EvidenceTier.CRYPTO_CONSTANT,
                matcher="const.aes.sbox",
                collector="elf",
            ),
        ]
    )
    assert merged[0].confidence == pytest.approx(0.985, abs=1e-3)


def test_duplicate_witnesses_do_not_inflate_confidence():
    """The same matcher firing twice is one witness, not two.

    Without de-duplication a collector that reports a rule per call site would
    manufacture near-certainty out of one weak signal.
    """
    duplicated = merge([finding(matcher="rule.a"), finding(matcher="rule.a", path="b.c")])
    single = merge([finding(matcher="rule.a")])
    assert duplicated[0].confidence == single[0].confidence


def test_confidence_is_capped_below_certainty():
    evidence = [Evidence(tier=EvidenceTier.NEGOTIATED, matcher_id="m%d" % i) for i in range(5)]
    assert combine_confidence(evidence) == 0.99


def test_negotiated_evidence_alone_sits_at_the_ceiling():
    assert combine_confidence([Evidence(tier=EvidenceTier.NEGOTIATED, matcher_id="tls")]) == 0.99


def test_no_evidence_is_zero_confidence():
    assert combine_confidence([]) == 0.0


def test_merge_output_is_deterministic():
    """Ordering must not depend on which collector finished first."""
    a = finding(matcher="rule.a")
    b = finding(name="RSA-2048", parameters={"key_size": 2048}, matcher="rule.b")
    forward = [m.finding.bom_ref() for m in merge([a, b])]
    backward = [m.finding.bom_ref() for m in merge([b, a])]
    assert forward == backward


def test_blast_radius_counts_distinct_targets():
    merged = merge(
        [
            finding(target="repo-a"),
            finding(target="repo-b"),
            finding(target="repo-c"),
            finding(target="repo-a", name="RSA-2048", parameters={"key_size": 2048}),
        ]
    )
    radius = blast_radius(merged)
    assert radius["AES-256-GCM"] == 3
    assert radius["RSA-2048"] == 1
