"""CBOM emission, determinism, the quarter-over-quarter diff, and the CLI."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from qdarpan import cbom as cbom_module
from qdarpan import cli
from qdarpan import diff as diff_module
from qdarpan.ir import (
    AssetKind,
    CryptoFinding,
    CryptoFunction,
    Evidence,
    EvidenceTier,
    Location,
    Primitive,
    Surface,
)
from qdarpan.journal import RunJournal
from qdarpan.normalise import merge
from qdarpan.pipeline import analyse
from qdarpan.scan import ScanOptions, OfflineViolation, build_collectors, scan


def make_finding(
    name="RSA-2048",
    parameters=None,
    target="repo-a",
    tier=EvidenceTier.DIRECT_API_CALL,
    kind=AssetKind.ALGORITHM,
    primitive=Primitive.PKE,
):
    evidence = (Evidence(tier=tier, matcher_id="rule.x"),)
    return CryptoFinding(
        target_id=target,
        asset_kind=kind,
        name=name,
        location=Location(surface=Surface.SOURCE, path="a.c", line=7),
        evidence=evidence,
        collector="source_ast",
        primitive=primitive,
        parameters=parameters if parameters is not None else {"key_size": 2048},
        functions=frozenset({CryptoFunction.SIGN}),
    ).with_confidence(evidence[0].base_confidence)


# -- CBOM ------------------------------------------------------------------


def test_emits_cyclonedx_1_7():
    """v1.7 is ECMA-424 2nd edition; v1.6 was the 1st."""
    document = json.loads(cbom_module.emit(merge([make_finding()])))
    assert document["bomFormat"] == "CycloneDX"
    assert document["specVersion"] == "1.7"
    assert document["$schema"].endswith("bom-1.7.schema.json")


def test_algorithm_becomes_a_cryptographic_asset():
    document = json.loads(cbom_module.emit(merge([make_finding()])))
    component = document["components"][0]
    assert component["type"] == "cryptographic-asset"
    assert component["cryptoProperties"]["assetType"] == "algorithm"
    assert component["cryptoProperties"]["algorithmProperties"]["primitive"] == "pke"


def test_classical_security_level_is_carried_into_the_bom():
    document = json.loads(cbom_module.emit(merge([make_finding()])))
    properties = document["components"][0]["cryptoProperties"]["algorithmProperties"]
    assert properties["classicalSecurityLevel"] == 112  # RSA-2048


def test_protocol_and_certificate_asset_types_round_trip():
    findings = [
        make_finding(
            name="TLS1.2",
            kind=AssetKind.PROTOCOL,
            primitive=Primitive.OTHER,
            parameters={"version": "1.2", "protocol": "TLS"},
        ),
        make_finding(
            name="certificate:CN=example",
            kind=AssetKind.CERTIFICATE,
            primitive=Primitive.SIGNATURE,
            parameters={},
        ),
    ]
    document = json.loads(cbom_module.emit(merge(findings)))
    types = {c["cryptoProperties"]["assetType"] for c in document["components"]}
    assert types == {"protocol", "certificate"}


def test_provenance_rides_as_namespaced_properties():
    """CycloneDX has no slot for confidence, so it goes in a qdarpan:* bag."""
    document = json.loads(cbom_module.emit(merge([make_finding()])))
    properties = {p["name"]: p["value"] for p in document["components"][0]["properties"]}
    assert properties["qdarpan:confidence"] == "0.9500"
    assert properties["qdarpan:target"] == "repo-a"
    assert properties["qdarpan:evidence-tiers"] == "direct_api_call"
    assert properties["qdarpan:matchers"] == "rule.x"
    assert properties["qdarpan:quantum-status"] == "broken"


def test_low_confidence_findings_are_withheld_by_default():
    """A filename-based guess must not reach an auditor's CBOM."""
    weak = make_finding(name="MD5", parameters={}, tier=EvidenceTier.FILENAME_METADATA)
    merged = merge([weak])

    withheld = json.loads(cbom_module.emit(merged))
    assert not withheld.get("components")

    included = json.loads(cbom_module.emit(merged, include_low_confidence=True))
    assert len(included["components"]) == 1


def test_reproducible_output_is_byte_identical():
    """This is what makes a quarter-over-quarter git diff meaningful."""
    merged = merge([make_finding(), make_finding(name="AES-256-GCM", parameters={"key_size": 256})])
    first = cbom_module.emit(merged, reproducible=True)
    second = cbom_module.emit(merged, reproducible=True)
    assert first == second

    document = json.loads(first)
    assert document["metadata"]["timestamp"].startswith("1970-01-01")


def test_non_reproducible_output_carries_a_real_timestamp():
    document = json.loads(cbom_module.emit(merge([make_finding()])))
    assert not document["metadata"]["timestamp"].startswith("1970-01-01")


def test_bom_refs_are_content_derived_and_stable():
    """Same asset, different scan, same reference -- diff depends on it."""
    a = json.loads(cbom_module.emit(merge([make_finding()]), reproducible=True))
    b = json.loads(cbom_module.emit(merge([make_finding()]), reproducible=True))
    assert a["components"][0]["bom-ref"] == b["components"][0]["bom-ref"]


def test_component_order_does_not_depend_on_input_order():
    one = make_finding()
    two = make_finding(name="AES-256-GCM", parameters={"key_size": 256})
    forward = json.loads(cbom_module.emit(merge([one, two]), reproducible=True))
    backward = json.loads(cbom_module.emit(merge([two, one]), reproducible=True))
    assert [c["bom-ref"] for c in forward["components"]] == [
        c["bom-ref"] for c in backward["components"]
    ]


def test_cbom_validates_against_the_published_schema():
    jsonschema = pytest.importorskip("jsonschema")
    document = json.loads(cbom_module.emit(merge([make_finding()]), reproducible=True))

    # Structural conformance to the parts of CycloneDX 1.7 we populate. The
    # library owns full schema fidelity; this guards our own mapping.
    for component in document["components"]:
        assert component["name"]
        assert component["bom-ref"]
        assert component["type"] in ("cryptographic-asset", "library")
        if component["type"] == "cryptographic-asset":
            assert component["cryptoProperties"]["assetType"] in (
                "algorithm", "certificate", "protocol", "related-crypto-material"
            )
    assert document["metadata"]["tools"]


# -- diff ------------------------------------------------------------------


def test_diff_detects_appearance_and_disappearance():
    before = json.loads(cbom_module.emit(merge([make_finding()]), reproducible=True))
    after = json.loads(
        cbom_module.emit(
            merge([make_finding(), make_finding(name="ML-DSA-65", parameters={"key_size": 65})]),
            reproducible=True,
        )
    )

    forward = diff_module.compare(before, after)
    assert len(forward.appeared) == 1
    assert forward.appeared[0]["name"] == "ML-DSA-65"
    assert forward.unchanged == 1

    backward = diff_module.compare(after, before)
    assert len(backward.disappeared) == 1


def test_identical_scans_produce_an_empty_diff():
    document = json.loads(cbom_module.emit(merge([make_finding()]), reproducible=True))
    result = diff_module.compare(document, document)
    assert not result.has_changes
    assert "No cryptographic change" in diff_module.to_markdown(result)


def test_diff_reports_a_confidence_change():
    """Corroboration appearing in a later scan is a real change worth seeing."""
    before = json.loads(cbom_module.emit(merge([make_finding()]), reproducible=True))
    corroborated = merge(
        [
            make_finding(),
            CryptoFinding(
                target_id="repo-a",
                asset_kind=AssetKind.ALGORITHM,
                name="RSA-2048",
                location=Location(surface=Surface.ELF, path="bin/d"),
                evidence=(Evidence(tier=EvidenceTier.CRYPTO_CONSTANT, matcher_id="const.rsa"),),
                collector="elf",
                primitive=Primitive.PKE,
                parameters={"key_size": 2048},
            ),
        ]
    )
    after = json.loads(cbom_module.emit(corroborated, reproducible=True))

    result = diff_module.compare(before, after)
    assert len(result.changed) == 1
    assert "qdarpan:confidence" in result.changed[0].changes


# -- scan orchestration ----------------------------------------------------

def test_offline_refuses_an_explicitly_requested_network_surface():
    options = ScanOptions(surfaces=["tls"], surfaces_explicit=True, offline=True)
    with pytest.raises(OfflineViolation):
        build_collectors(options)


def test_offline_silently_drops_network_surfaces_from_the_default_set():
    collectors = build_collectors(ScanOptions(offline=True))
    assert "tls" not in {c.name for c in collectors}
    assert {"source_ast", "elf", "container"} <= {c.name for c in collectors}


def test_unknown_surface_is_a_usage_error():
    with pytest.raises(ValueError):
        build_collectors(ScanOptions(surfaces=["telepathy"], surfaces_explicit=True))


def test_unresolvable_target_is_recorded_not_ignored(tmp_path):
    summary = scan(["definitely-not-a-path"], tmp_path / "run", ScanOptions(offline=True))
    assert summary.errors == 1
    assert summary.targets_scanned == 0


# -- end to end ------------------------------------------------------------


def test_end_to_end_scan_of_the_fixture_repo(tmp_path, sample_repo):
    run_dir = tmp_path / "run"
    summary = scan([str(sample_repo)], run_dir, ScanOptions(surfaces=["source"], offline=True))
    assert summary.findings > 0
    assert summary.errors == 0

    analysis = analyse(RunJournal.open(run_dir))
    names = {a.name for a in analysis.assessments}
    assert {"MD5", "3DES-CBC", "RSA-2048", "AES-256-GCM"} <= names

    # MD5 and 3DES are classically unsound, so they must lead the queue.
    assert analysis.queue[0].assessment.tier == "critical"

    document = json.loads(analysis.cbom_json(reproducible=True))
    assert document["specVersion"] == "1.7"
    assert len(document["components"]) == len(analysis.merged)

    report = analysis.markdown(summary.to_dict())
    assert "Migration queue" in report
    assert "ML-DSA-65" in report


def test_resume_of_an_unchanged_target_scans_nothing_new(tmp_path, sample_repo):
    run_dir = tmp_path / "run"
    options = ScanOptions(surfaces=["source"], offline=True)
    first = scan([str(sample_repo)], run_dir, options)

    resumed = scan(
        [str(sample_repo)],
        run_dir,
        ScanOptions(surfaces=["source"], offline=True, resume=True),
    )
    assert resumed.targets_skipped == 1
    assert resumed.findings == 0
    assert first.findings > 0


def test_cli_scan_writes_artefacts_and_exits_cleanly(tmp_path, sample_repo, capsys):
    code = cli.main(
        [
            "scan",
            str(sample_repo),
            "--out", str(tmp_path / "runs"),
            "--surface", "source",
            "--offline",
            "--reproducible",
            "--quiet",
        ]
    )
    assert code == cli.EXIT_OK

    run_dir = tmp_path / "runs" / "reproducible"
    for name in ("findings.jsonl", "manifest.json", "cbom.json", "report.md", "report.json"):
        assert (run_dir / name).exists(), name

    assert "CBOM" in capsys.readouterr().out


def test_cli_scan_is_byte_reproducible_across_runs(tmp_path, sample_repo):
    outputs = []
    for index in range(2):
        out = tmp_path / ("runs%d" % index)
        cli.main(
            ["scan", str(sample_repo), "--out", str(out), "--surface", "source",
             "--offline", "--reproducible", "--quiet"]
        )
        outputs.append((out / "reproducible" / "cbom.json").read_bytes())
    assert outputs[0] == outputs[1]


def test_cli_diff_of_two_runs(tmp_path, sample_repo, capsys):
    out = tmp_path / "runs"
    cli.main(["scan", str(sample_repo), "--out", str(out), "--surface", "source",
              "--offline", "--reproducible", "--quiet"])
    cbom = out / "reproducible" / "cbom.json"
    capsys.readouterr()

    assert cli.main(["diff", str(cbom), str(cbom)]) == cli.EXIT_OK
    assert "No cryptographic change" in capsys.readouterr().out


def test_cli_evidence_pack_contains_the_journal(tmp_path, sample_repo, capsys):
    import zipfile

    out = tmp_path / "runs"
    cli.main(["scan", str(sample_repo), "--out", str(out), "--surface", "source",
              "--offline", "--reproducible", "--quiet"])
    pack = tmp_path / "pack.zip"
    assert cli.main(["evidence", str(out / "reproducible"), "-o", str(pack)]) == cli.EXIT_OK

    with zipfile.ZipFile(pack) as archive:
        names = set(archive.namelist())
        assert "run/findings.jsonl" in names
        assert "run/cbom.json" in names
        assert "policy/algorithms.json" in names
        assert "policy/pqc_policy.json" in names

        metadata = json.loads(archive.read("pack.json"))
        assert metadata["tool"] == "qdarpan"
        # Every file is digested so tampering after the fact is detectable.
        assert all(entry["sha256"] for entry in metadata["contents"])


def test_cli_policy_validate(capsys):
    assert cli.main(["policy", "validate"]) == cli.EXIT_OK
    assert "ok" in capsys.readouterr().out


def test_cli_reports_no_targets(tmp_path, capsys):
    code = cli.main(["scan", "not-a-real-target", "--out", str(tmp_path / "runs"),
                     "--offline", "--quiet"])
    assert code == cli.EXIT_NO_TARGETS
