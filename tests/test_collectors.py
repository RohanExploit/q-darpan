"""The four discovery surfaces, each against a real input."""

from __future__ import annotations

from pathlib import Path

import pytest

from qdarpan.collectors.base import TargetKind, classify
from qdarpan.collectors.container import ContainerCollector
from qdarpan.collectors.elf import ELFCollector
from qdarpan.collectors.source_ast import SourceASTCollector
from qdarpan.collectors.tls import TLSCollector
from qdarpan.ir import AssetKind, CryptoFinding, EvidenceTier, Surface


def findings(results):
    return [r for r in results if isinstance(r, CryptoFinding)]


def errors(results):
    return [r for r in results if not isinstance(r, CryptoFinding)]


def names(results):
    return {f.name for f in findings(results)}


# -- target classification -------------------------------------------------


def test_classify_distinguishes_targets(tmp_path):
    directory = tmp_path / "repo"
    directory.mkdir()
    tarball = tmp_path / "image.tar"
    tarball.write_bytes(b"")

    assert classify(str(directory)).kind == TargetKind.DIRECTORY
    assert classify(str(tarball)).kind == TargetKind.CONTAINER
    assert classify("example.com:443").kind == TargetKind.ENDPOINT
    assert classify("not-a-real-thing").kind == TargetKind.UNKNOWN


def test_existing_path_beats_the_endpoint_pattern(tmp_path):
    """A directory named like an endpoint is still a directory."""
    odd = tmp_path / "example.com:443"
    try:
        odd.mkdir()
    except OSError:
        pytest.skip("filesystem rejects ':' in names")
    assert classify(str(odd)).kind == TargetKind.DIRECTORY


# -- source AST ------------------------------------------------------------


def test_source_collector_finds_c_openssl_calls(sample_repo):
    results = SourceASTCollector().safe_collect(classify(str(sample_repo)))
    assert not errors(results)
    found = names(results)

    # C is the differentiator: sonar-cryptography has no C/C++ support.
    assert "AES-256-GCM" in found
    assert "3DES-CBC" in found
    assert "RSA-2048" in found
    assert "ECDSA-P-256" in found
    assert "MD5" in found


def test_source_collector_reads_cpp(sample_repo):
    results = SourceASTCollector().safe_collect(classify(str(sample_repo)))
    cpp = [f for f in findings(results) if f.location.path.endswith(".cpp")]
    assert {f.name for f in cpp} >= {"RC4", "SHA-1"}


def test_source_collector_splits_java_transformations(sample_repo):
    results = SourceASTCollector().safe_collect(classify(str(sample_repo)))
    java = {f.name: f for f in findings(results) if f.location.path.endswith(".java")}

    assert "AES-GCM" in java
    assert java["AES-GCM"].parameters["mode"] == "gcm"
    assert java["AES-GCM"].parameters["padding"] == "raw"  # NoPadding
    assert java["DES-CBC"].parameters["padding"] == "pkcs5"


def test_java_keysize_is_absent_when_the_source_does_not_state_it(sample_repo):
    """`Cipher.getInstance("AES/GCM/NoPadding")` names no key size, so neither do we."""
    results = SourceASTCollector().safe_collect(classify(str(sample_repo)))
    aes = next(f for f in findings(results) if f.name == "AES-GCM")
    assert aes.parameters.get("key_size") is None


def test_source_collector_reads_go_selector_calls(sample_repo):
    results = SourceASTCollector().safe_collect(classify(str(sample_repo)))
    go = {f.name for f in findings(results) if f.location.path.endswith(".go")}
    assert {"RSA-2048", "ECDSA-P-256", "MD5", "SHA-256"} <= go


def test_source_findings_carry_traceable_evidence(sample_repo):
    results = SourceASTCollector().safe_collect(classify(str(sample_repo)))
    for item in findings(results):
        assert item.evidence
        assert item.evidence[0].matcher_id  # a rule id a reviewer can look up
        assert item.location.line is not None or item.asset_kind is AssetKind.LIBRARY
        assert 0.0 < item.confidence <= 0.99


def test_unresolvable_literal_argument_degrades_rather_than_guessing(tmp_path):
    """A key size passed as a variable is unknown, not assumed."""
    source = tmp_path / "dynamic.c"
    source.write_text(
        "#include <openssl/rsa.h>\n"
        "int f(RSA *r, int bits, BIGNUM *e) { return RSA_generate_key_ex(r, bits, e, 0); }\n",
        encoding="utf-8",
    )
    results = SourceASTCollector().safe_collect(classify(str(tmp_path)))
    rsa = next(f for f in findings(results) if f.name.startswith("RSA"))
    assert rsa.name == "RSA"
    assert rsa.evidence[0].tier is EvidenceTier.LINKED_LIBRARY_PINNED
    assert rsa.confidence < 0.95


# -- ELF -------------------------------------------------------------------


def test_elf_collector_reads_linkage_symbols_and_constants(elf_tree):
    results = ELFCollector().safe_collect(classify(str(elf_tree)))
    assert not errors(results)

    by_matcher = {f.evidence[0].matcher_id: f for f in findings(results)}
    assert "dt_needed.openssl" in by_matcher
    assert "openssl.rsa.generate_key_ex" in by_matcher
    assert "const.aes.sbox" in by_matcher
    assert "const.md5.t_be" in by_matcher


def test_elf_constant_hits_sit_below_symbol_hits(elf_tree):
    """A constant proves presence; a symbol proves the call. Score them apart."""
    results = findings(ELFCollector().safe_collect(classify(str(elf_tree))))
    constant = next(f for f in results if f.evidence[0].tier is EvidenceTier.CRYPTO_CONSTANT)
    symbol = next(f for f in results if f.evidence[0].tier is EvidenceTier.LINKED_LIBRARY_PINNED)
    assert constant.confidence < symbol.confidence


def test_elf_constant_records_its_offset(elf_tree):
    results = findings(ELFCollector().safe_collect(classify(str(elf_tree))))
    constant = next(f for f in results if f.evidence[0].matcher_id == "const.aes.sbox")
    assert constant.location.offset is not None
    assert constant.evidence[0].detail["section"] == ".rodata"


def test_malformed_binary_is_recorded_not_raised(tmp_path):
    """A truncated ELF is an expected condition on a real estate."""
    broken = tmp_path / "broken.so"
    broken.write_bytes(b"\x7fELF" + b"\x00" * 8)
    results = ELFCollector().safe_collect(classify(str(tmp_path)))
    assert errors(results)
    assert not findings(results)


# -- container -------------------------------------------------------------


def test_container_collector_walks_a_docker_save_tarball(image_tarball):
    results = ContainerCollector().safe_collect(classify(str(image_tarball)))
    found = names(results)
    assert "AES" in found            # from the S-box in the layer's binary
    assert "SHA-256" in found        # from the EVP_sha256 symbol
    assert "openssl" in found        # from the dpkg package database


def test_container_findings_carry_the_layer_digest(image_tarball):
    results = findings(ContainerCollector().safe_collect(classify(str(image_tarball))))
    assert any(f.location.layer_digest for f in results)


def test_container_findings_report_the_container_surface(image_tarball):
    """Binary analysis inside an image is still a container scan."""
    results = findings(ContainerCollector().safe_collect(classify(str(image_tarball))))
    assert {f.location.surface for f in results} == {Surface.CONTAINER}


def test_container_package_metadata_is_weak_evidence(image_tarball):
    """A package database entry is the weakest witness there is.

    Note that the layer produces two ``openssl`` library findings -- one from
    the binary's DT_NEEDED and one from the dpkg database -- so this selects by
    matcher rather than by name. Those two merging later is deliberate: it is
    what attributes a linked library to a package version.
    """
    results = findings(ContainerCollector().safe_collect(classify(str(image_tarball))))
    package = next(f for f in results if f.evidence[0].matcher_id == "package.dpkg")
    assert package.name == "openssl"
    assert package.evidence[0].tier is EvidenceTier.FILENAME_METADATA
    assert package.parameters["library_version"] == "3.0.2-0ubuntu1.15"


def test_container_attributes_a_linked_library_to_a_package_version(image_tarball):
    """DT_NEEDED says openssl is linked; dpkg says which version. Both are kept."""
    results = findings(ContainerCollector().safe_collect(classify(str(image_tarball))))
    matchers = {f.evidence[0].matcher_id for f in results if f.name == "openssl"}
    assert {"dt_needed.openssl", "package.dpkg"} <= matchers


def test_container_ignores_non_crypto_packages(image_tarball):
    assert "coreutils" not in names(ContainerCollector().safe_collect(classify(str(image_tarball))))


# -- TLS -------------------------------------------------------------------


def test_tls_collector_reports_what_was_negotiated(tls_server):
    results = TLSCollector(timeout=5).safe_collect(classify(tls_server))
    assert not errors(results)

    kinds = {f.asset_kind for f in findings(results)}
    assert AssetKind.PROTOCOL in kinds
    assert AssetKind.CERTIFICATE in kinds

    protocol = next(f for f in findings(results) if f.asset_kind is AssetKind.PROTOCOL)
    assert protocol.name.startswith("TLS1.")
    assert protocol.evidence[0].tier is EvidenceTier.NEGOTIATED


def test_tls_reads_the_certificate_public_key(tls_server):
    """The fixture serves RSA-2048, so that is what must come back."""
    results = findings(TLSCollector(timeout=5).safe_collect(classify(tls_server)))
    assert "RSA-2048" in {f.name for f in results}


def test_tls_decomposes_the_cipher_suite(tls_server):
    results = findings(TLSCollector(timeout=5).safe_collect(classify(tls_server)))
    algorithms = {f.name for f in results if f.asset_kind is AssetKind.ALGORITHM}
    assert any(name.startswith("AES") or name.startswith("ChaCha20") for name in algorithms)


def test_negotiated_evidence_outranks_everything(tls_server):
    results = findings(TLSCollector(timeout=5).safe_collect(classify(tls_server)))
    assert all(f.confidence == 0.99 for f in results)


def test_unreachable_endpoint_is_an_error_not_a_crash():
    # Port 1 on loopback: nothing listens there, and the failure must be recorded.
    results = TLSCollector(timeout=1).safe_collect(classify("127.0.0.1:1"))
    assert errors(results)
    assert not findings(results)
