"""Journal durability, the Mosca risk model, and the migration recommender."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from dataclasses import replace

from qdarpan.canonical import Registry
from qdarpan.ir import (
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
from qdarpan.journal import Manifest, RunJournal, content_hash
from qdarpan.normalise import merge
from qdarpan.recommend import CostModel, build_queue, recommend_for
from qdarpan.risk import (
    CRITICAL,
    HIGH,
    LOW,
    MEDIUM,
    PQ_SAFE,
    Policy,
    assess,
    assess_all,
    evaluate_mosca,
)


def make_finding(name="RSA-2048", parameters=None, target="repo-a", kind=AssetKind.ALGORITHM):
    evidence = (Evidence(tier=EvidenceTier.DIRECT_API_CALL, matcher_id="rule.x"),)
    return CryptoFinding(
        target_id=target,
        asset_kind=kind,
        name=name,
        location=Location(surface=Surface.SOURCE, path="a.c", line=7),
        evidence=evidence,
        collector="source_ast",
        primitive=Primitive.PKE,
        parameters=parameters if parameters is not None else {"key_size": 2048},
    ).with_confidence(0.95)


# -- journal ---------------------------------------------------------------


def test_journal_round_trips_findings(tmp_path):
    journal = RunJournal(tmp_path / "run")
    original = make_finding()
    journal.record_finding(original)

    replayed = list(RunJournal.open(tmp_path / "run").findings())
    assert len(replayed) == 1
    assert replayed[0].canonical_key() == original.canonical_key()
    assert replayed[0].confidence == original.confidence
    assert replayed[0].evidence[0].tier is EvidenceTier.DIRECT_API_CALL


def test_journal_survives_a_truncated_final_line(tmp_path):
    """A killed process leaves a half-written line. The rest must still load."""
    journal = RunJournal(tmp_path / "run")
    journal.record_finding(make_finding())
    journal.record_finding(make_finding(name="AES-256-GCM", parameters={"key_size": 256}))

    with open(journal.findings_path, "a", encoding="utf-8") as handle:
        handle.write('{"target_id": "repo-a", "asset_ki')

    assert len(list(RunJournal.open(tmp_path / "run").findings())) == 2


def test_journal_records_errors_separately(tmp_path):
    journal = RunJournal(tmp_path / "run")
    journal.record_error(
        CollectorError(target_id="repo-a", collector="elf", phase="read", reason="permission denied")
    )
    assert len(RunJournal.open(tmp_path / "run").errors()) == 1


def test_resume_skips_unchanged_targets(tmp_path):
    source = tmp_path / "repo"
    source.mkdir()
    (source / "a.c").write_text("int main(void){return 0;}", encoding="utf-8")

    journal = RunJournal(tmp_path / "run")
    digest = content_hash(source)
    journal.register_target(source.as_posix(), "directory", digest)
    journal.complete_target(source.as_posix())
    journal.save_manifest()

    reopened = RunJournal.open(tmp_path / "run")
    assert reopened.should_skip(source.as_posix(), digest)


def test_resume_rescans_when_content_changes(tmp_path):
    source = tmp_path / "repo"
    source.mkdir()
    (source / "a.c").write_text("int main(void){return 0;}", encoding="utf-8")

    journal = RunJournal(tmp_path / "run")
    journal.register_target(source.as_posix(), "directory", content_hash(source))
    journal.complete_target(source.as_posix())
    journal.save_manifest()

    (source / "b.c").write_text("int helper(void){return 1;}", encoding="utf-8")

    reopened = RunJournal.open(tmp_path / "run")
    assert not reopened.should_skip(source.as_posix(), content_hash(source))


def test_incomplete_target_is_not_skipped(tmp_path):
    """A target that errored last time gets another chance."""
    journal = RunJournal(tmp_path / "run")
    journal.register_target("repo-a", "directory", "abc")
    journal.save_manifest()
    assert not RunJournal.open(tmp_path / "run").should_skip("repo-a", "abc")


# -- Mosca -----------------------------------------------------------------


@pytest.fixture(scope="module")
def policy() -> Policy:
    return Policy.load()


def test_mosca_trips_when_migration_plus_shelf_life_exceeds_crqc(policy):
    result = evaluate_mosca(policy, migration_years=5, shelf_life_years=25)
    assert result.trips_all           # 30 years beats even the optimistic Z
    assert result.scenarios_tripped == 3


def test_mosca_holds_for_short_lived_data(policy):
    result = evaluate_mosca(policy, migration_years=1, shelf_life_years=2)
    assert result.scenarios_tripped == 0
    assert not result.trips_median


def test_mosca_reports_a_band_not_a_verdict(policy):
    """Z is contested, so partial results must be representable."""
    result = evaluate_mosca(policy, migration_years=3, shelf_life_years=7)
    assert 0 < result.scenarios_tripped < result.total_scenarios
    assert result.scenarios["pessimistic"]["trips"]
    assert not result.scenarios["optimistic"]["trips"]


def test_mosca_margin_is_signed(policy):
    result = evaluate_mosca(policy, migration_years=2, shelf_life_years=2)
    assert result.scenarios["median"]["margin_years"] == 10  # Z=14, X+Y=4


# -- risk tiers ------------------------------------------------------------


def test_classically_broken_outranks_quantum_risk(policy):
    """MD5 does not need a quantum computer to be a problem."""
    item = merge([make_finding(name="MD5", parameters={})])[0]
    result = assess(item, policy=policy, criticality="low")
    assert result.tier == CRITICAL
    assert result.classical_status == "broken"
    assert result.rationale == "Practical collisions since 2004."


def test_quantum_safe_algorithm_is_marked_pq_safe(policy):
    item = merge([make_finding(name="ML-KEM-768", parameters={"key_size": 768})])[0]
    assert assess(item, policy=policy).tier == PQ_SAFE


def test_long_lived_rsa_is_critical(policy):
    item = merge([make_finding(name="RSA-2048", parameters={"key_size": 2048})])[0]
    assert assess(item, policy=policy, criticality="critical").tier == CRITICAL


def test_short_lived_rsa_is_less_urgent(policy):
    """Same algorithm, different data shelf life, different answer."""
    item = merge([make_finding(name="RSA-2048", parameters={"key_size": 2048})])[0]
    assert assess(item, policy=policy, criticality="low").tier in (LOW, MEDIUM)


def test_unknown_algorithm_is_not_graded_safe(policy):
    """A registry gap must not read as an all-clear."""
    item = merge([make_finding(name="SnakeOil-9000", parameters={})])[0]
    result = assess(item, policy=policy)
    assert result.tier != PQ_SAFE
    assert result.quantum_status == "unknown"


def test_deprecation_deadlines_attach_to_112_bit_assets(policy):
    item = merge([make_finding(name="RSA-2048", parameters={"key_size": 2048})])[0]
    ids = {d.id for d in assess(item, policy=policy).deadlines}
    assert "nist-ir8547-deprecated" in ids
    assert "nist-ir8547-disallowed" in ids


def test_stronger_keys_skip_the_112_bit_deadline(policy):
    item = merge([make_finding(name="RSA-4096", parameters={"key_size": 4096})])[0]
    ids = {d.id for d in assess(item, policy=policy).deadlines}
    assert "nist-ir8547-deprecated" not in ids
    assert "nist-ir8547-disallowed" in ids  # still quantum-vulnerable


def test_pq_safe_assets_carry_no_algorithm_deadlines(policy):
    item = merge([make_finding(name="ML-DSA-65", parameters={"key_size": 65})])[0]
    result = assess(item, policy=policy)
    assert not [d for d in result.deadlines if d.id.startswith("nist-ir8547")]


def test_assessments_are_ordered_most_urgent_first(policy):
    merged = merge(
        [
            make_finding(name="ML-KEM-768", parameters={"key_size": 768}, target="a"),
            make_finding(name="MD5", parameters={}, target="b"),
            make_finding(name="RSA-2048", parameters={"key_size": 2048}, target="c"),
        ]
    )
    tiers = [a.tier for a in assess_all(merged, policy=policy, criticality_by_target={})]
    assert tiers[0] == CRITICAL
    assert tiers[-1] == PQ_SAFE


# -- recommender -----------------------------------------------------------


@pytest.fixture(scope="module")
def costs() -> CostModel:
    return CostModel.load()


def test_rsa_signature_maps_to_ml_dsa(costs, policy):
    """RSA is filed under `pke` in the registry, but a signing site is a signature."""
    finding = replace(
        make_finding(name="RSA-2048", parameters={"key_size": 2048}),
        functions=frozenset({CryptoFunction.SIGN, CryptoFunction.VERIFY}),
    )
    recommendation = recommend_for(assess(merge([finding])[0], policy=policy), costs=costs)
    assert recommendation.target == "ML-DSA-65"
    assert recommendation.standard == "FIPS 204"


def test_rsa_key_transport_maps_to_ml_kem(costs, policy):
    """Same algorithm, different observed role, different destination."""
    finding = replace(
        make_finding(name="RSA-2048", parameters={"key_size": 2048}),
        functions=frozenset({CryptoFunction.KEYDERIVE}),
    )
    recommendation = recommend_for(assess(merge([finding])[0], policy=policy), costs=costs)
    assert recommendation.target == "ML-KEM-768"
    assert recommendation.hybrid == "X25519MLKEM768"


def test_rsa_with_no_observed_role_defaults_to_signature(costs, policy):
    """Certificates are where RSA overwhelmingly turns up, so that is the default."""
    item = merge([make_finding(name="RSA-2048", parameters={"key_size": 2048})])[0]
    assert recommend_for(assess(item, policy=policy), costs=costs).target == "ML-DSA-65"


def test_ecdh_maps_to_ml_kem_with_a_hybrid_option(costs, policy):
    finding = make_finding(name="ECDH-P-256", parameters={"curve": "P-256"})
    recommendation = recommend_for(assess(merge([finding])[0], policy=policy), costs=costs)
    assert recommendation.target == "ML-KEM-768"
    assert recommendation.hybrid == "X25519MLKEM768"  # RFC 10024


def test_size_deltas_match_the_fips_standards(costs):
    """The deck's headline number, checked against FIPS 204 and SEC 1."""
    recommendation = costs.recommend("ECDSA", "ECDSA-P256", ["signature"])
    by_field = {d.field: d for d in recommendation.size_deltas}

    assert by_field["public_key"].before == 64
    assert by_field["public_key"].after == 1952
    assert by_field["public_key"].delta == 1888

    assert by_field["signature"].before == 64
    assert by_field["signature"].after == 3309
    assert by_field["signature"].ratio == pytest.approx(51.7, abs=0.05)


def test_deltas_only_compare_fields_both_algorithms_define(costs):
    """A KEM has a ciphertext and no signature; do not invent a comparison."""
    recommendation = costs.recommend("ECDH", "X25519", ["key-agree"])
    fields = {d.field for d in recommendation.size_deltas}
    assert "signature" not in fields
    assert "ciphertext" in fields


def test_quantum_safe_assets_get_no_recommendation(costs, policy):
    item = merge([make_finding(name="ML-DSA-65", parameters={"key_size": 65})])[0]
    assert recommend_for(assess(item, policy=policy), costs=costs) is None


def test_aes_128_is_told_to_grow_not_to_go_post_quantum(costs, policy):
    item = merge([make_finding(name="AES-128", parameters={"key_size": 128})])[0]
    recommendation = recommend_for(assess(item, policy=policy), costs=costs)
    assert recommendation.target == "AES-256"


def test_queue_ranks_blast_radius_above_cost(policy, costs):
    """Between two equally risky assets, the widespread one goes first."""
    merged = merge(
        [
            make_finding(name="RSA-2048", parameters={"key_size": 2048}, target="repo-%d" % i)
            for i in range(3)
        ]
        + [make_finding(name="DSA-2048", parameters={"key_size": 2048}, target="repo-z")]
    )
    assessments = assess_all(merged, policy=policy)
    queue = build_queue(assessments, merged, costs=costs)
    top = queue[0]
    assert top.assessment.name == "RSA-2048"
    assert top.blast_radius == 3
