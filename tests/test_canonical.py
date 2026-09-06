"""Canonicalisation: every ecosystem's spelling must land on one registry entry."""

from __future__ import annotations

import pytest

from qdarpan.canonical import Registry, UnknownAlgorithm
from qdarpan.ir import Primitive


@pytest.fixture(scope="module")
def registry() -> Registry:
    return Registry.load()


@pytest.mark.parametrize(
    "raw,parameters,expected_name,expected_family",
    [
        # OpenSSL C spellings, where the family sits in the middle of the token run.
        ("EVP_aes_256_gcm", {"key_size": 256, "mode": "gcm"}, "AES-256-GCM", "AES"),
        ("EVP_sha384", {}, "SHA-384", "SHA-2"),
        ("EVP_sha256", {}, "SHA-256", "SHA-2"),
        # Java JCA and X.509 spellings.
        ("SHA-256", {}, "SHA-256", "SHA-2"),
        ("sha256WithRSAEncryption", {}, "RSA", "RSA"),
        ("SHA256withRSA", {}, "RSA", "RSA"),
        # Curve aliases.
        ("ECDSA", {"curve": "prime256v1"}, "ECDSA-P-256", "ECDSA"),
        ("ECDSA", {"curve": "secp384r1"}, "ECDSA-P-384", "ECDSA"),
        # Post-quantum parameter sets.
        ("ML-KEM-1024", {}, "ML-KEM-1024", "ML-KEM"),
        ("Kyber", {}, "ML-KEM-768", "ML-KEM"),
        ("Dilithium", {}, "ML-DSA-65", "ML-DSA"),
        # Legacy.
        ("3DES", {}, "3DES", "3DES"),
        ("desede", {}, "3DES", "3DES"),
    ],
)
def test_canonical_names(registry, raw, parameters, expected_name, expected_family):
    canonical = registry.canonicalise(raw, parameters)
    assert canonical.name == expected_name
    assert canonical.family == expected_family


def test_unqualified_detection_does_not_invent_a_key_size(registry):
    """A bare RSA sighting must not silently become RSA-2048.

    Inventing a parameter would put a key size into an auditor's CBOM that
    nobody observed, which is worse than reporting the gap.
    """
    canonical = registry.canonicalise("RSA", {})
    assert canonical.name == "RSA"
    assert canonical.parameters.get("key_size") is None
    assert canonical.security_bits == 0


def test_standard_named_parameter_sets_keep_their_default(registry):
    """ML-KEM without a suffix means ML-KEM-768; the standard names the set."""
    assert registry.canonicalise("ML-KEM", {}).name == "ML-KEM-768"


def test_key_size_is_chosen_from_the_family_table(registry):
    """A name carrying several numbers resolves to the one the family defines."""
    canonical = registry.canonicalise("TLS_AES_256_GCM_SHA384", {})
    assert canonical.family == "AES"
    assert canonical.parameters["key_size"] == 256


def test_quantum_status_and_levels(registry):
    rsa = registry.canonicalise("RSA", {"key_size": 2048})
    assert rsa.quantum_status == "broken"
    assert rsa.security_bits == 112
    assert rsa.quantum_security_bits == 0  # Shor leaves nothing

    aes128 = registry.canonicalise("AES", {"key_size": 128})
    assert aes128.quantum_status == "weakened"
    assert aes128.quantum_security_bits == 64  # Grover halves it

    aes256 = registry.canonicalise("AES", {"key_size": 256})
    assert aes256.quantum_security_bits == 128

    sha256 = registry.canonicalise("SHA-256", {})
    assert sha256.quantum_status == "safe"


def test_classically_broken_is_flagged_separately_from_quantum(registry):
    md5 = registry.canonicalise("MD5", {})
    assert md5.classical_status == "broken"
    assert md5.classical_note

    triple_des = registry.canonicalise("3DES", {})
    assert triple_des.classical_status == "disallowed"


def test_primitive_matches_cyclonedx_vocabulary(registry):
    assert registry.canonicalise("ML-KEM-768", {}).primitive is Primitive.KEM
    assert registry.canonicalise("ML-DSA-65", {}).primitive is Primitive.SIGNATURE
    assert registry.canonicalise("SHA-256", {}).primitive is Primitive.HASH


def test_unknown_algorithm_raises_rather_than_guessing(registry):
    with pytest.raises(UnknownAlgorithm):
        registry.canonicalise("SnakeOil-9000", {})


def test_oids_are_resolved_where_the_registry_has_them(registry):
    assert registry.canonicalise("RSA", {"key_size": 2048}).oid == "1.2.840.113549.1.1.1"
    assert registry.canonicalise("AES", {"key_size": 256}).oid == "2.16.840.1.101.3.4.1.42"
