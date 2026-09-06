# Q-DARPAN — Design Specification

**Problem Statement:** SIH26164 — Enterprise Cryptographic Discovery & Analysis Tool (ECDAT)
**Theme:** Blockchain & Cybersecurity · **Category:** Software
**Date:** 2026-09-07
**Status:** Approved design, implementation in progress

---

## 1. Purpose

Q-DARPAN discovers cryptographic assets across an enterprise estate, emits a standards-conformant
Cryptographic Bill of Materials (CBOM), scores each asset for quantum risk, and ranks a migration
queue toward NIST post-quantum standards.

It runs entirely on-premises with no network egress, no agents, and no GPU.

### Target user

A SOC or infrastructure team at an Indian Critical Information Infrastructure (CII) operator —
state data centre, PSU, bank — that must produce a cryptographic inventory and a quantum-migration
plan, and will be asked for vendor CBOMs from FY 2027-28 under the DST National Quantum Mission
Quantum Safe Ecosystem Task Force report (4 Feb 2026).

### Success criteria

1. `qdarpan scan` runs on a mixed target set (source tree, ELF binaries, container tarball, TLS
   endpoint) and produces a valid CycloneDX 1.7 CBOM in a single pass.
2. Output validates against the published CycloneDX 1.7 JSON schema.
3. Re-running the same scan on unchanged inputs produces a byte-identical CBOM under
   `--reproducible`.
4. Every finding carries an evidence record and a confidence score derived from a published ladder.
5. Precision and recall are measured per collector against a labelled fixture corpus and reported
   in the README — not asserted.
6. Full offline install from a vendored wheel bundle, verified on a machine with networking
   disabled.

### Non-goals

- Not a CVE scanner. Q-DARPAN inventories cryptography; it does not enumerate vulnerabilities.
- Not an automatic code rewriter. It recommends and ranks; a human performs the migration.
- No cloud service, no telemetry, no phone-home. Ever.
- No machine learning, no model weights, no GPU dependency.
- Not a general SBOM tool. Package inventory is in scope only where it evidences cryptography.

---

## 2. Verified external facts

Checked on 2026-09-07. Several correct errors in the submitted deck.

| Fact | Status |
|---|---|
| ECMA-424 1st edition = CycloneDX v1.6 (Jun 2024); **2nd edition = CycloneDX v1.7 (Dec 2025)** | Verified at ecma-international.org |
| `cyclonedx-python-lib` 11.11.0 exposes `SchemaVersion.V1_7` and the full `cyclonedx.model.crypto` CBOM model | Verified in the local interpreter |
| `sonar-cryptography` (now `cbomkit/sonar-cryptography`) supports Java, Python, Go and **C# as of v1.7.0 (1 Sep 2026)**. No C/C++. | Verified against LANGUAGE_SUPPORT.md and the releases API |
| RFC 10024, *PQ/T Hybrid Key Agreement Mechanisms for TLS 1.3*, Standards Track, Aug 2026. Defines X25519MLKEM768, SecP256r1MLKEM768, SecP384r1MLKEM1024. Framework is RFC 9954. | Verified at datatracker.ietf.org |
| NIST IR 8547 is still **Initial Public Draft** (12 Nov 2024). 112-bit RSA/ECC deprecated after 2030, disallowed after 2035. | Verified at csrc.nist.gov |
| FIPS 203 (ML-KEM), 204 (ML-DSA), 205 (SLH-DSA), Aug 2024 | Final standards |

**Deck consequence:** the C/C++ differentiator survives, but the wording "Java, Python, Go only" is
stale and must become "Java, Python, Go, C# — no C/C++". The ECMA-424 mapping appears twice in the
deck and contradicts itself; it must be stated once, correctly.

---

## 3. Constraints

| Constraint | Consequence |
|---|---|
| Air-gapped enclave, no egress | Vendored wheel bundle; pinned grammars; zero network calls during scan except the deliberate TLS probe |
| Project lives on `E:\q-darpan` | The original `R:` volume dismounted mid-build on 2026-09-07 and is not a physical partition. venv, caches and scan artifacts all stay on E: |
| No Docker daemon available | Container collector reads `docker save` tarballs, OCI layouts, and extracted rootfs directories. No daemon, no registry |
| CPU-bound workload, laptop-class GPU | No GPU code path at all. Stated as a feature: runs on any analyst laptop |
| Python 3.10.0 is the installed interpreter | Target `>=3.10`. No PEP 695 generics, no 3.11+ stdlib |
| Estate scale: ~412 repos, ~190 images, ~2,300 TLS endpoints | Scans must be resumable, incremental, and bounded in memory |

### Dependency budget

New dependencies total roughly 15 MB:

- `tree-sitter` plus `tree-sitter-c`, `tree-sitter-cpp`, `tree-sitter-java`, `tree-sitter-go` (~10 MB)
- `pyelftools` (~2 MB)

Plus `cryptography`, `cyclonedx-python-lib`, `fastapi`, `uvicorn`, `pytest`.

**Explicitly rejected:** `syft` (~80 MB Go binary, assumes a daemon or registry), Docker,
Node/npm/React, any ML runtime.

---

## 4. Architecture

Four collectors feed a neutral intermediate representation. A normaliser deduplicates across
surfaces. One emitter converts the IR to CycloneDX 1.7. The risk engine and recommender read the
IR, not the BOM.

```
targets ──┬─> source_ast  ─┐
          ├─> elf         ─┤
          ├─> container   ─┼─> [CryptoFinding] ─> normalise ─┬─> cbom.py  ─> CycloneDX 1.7 JSON
          └─> tls         ─┘         (JSONL journal)         ├─> risk.py  ─> Mosca bands
                                                             └─> recommend.py ─> ranked queue
```

**Why a neutral IR rather than building CycloneDX objects directly:** confidence and evidence are
first-class in the IR but have no clean home in the CycloneDX crypto model (they would be stuffed
into a `properties` bag). The risk engine would otherwise have to re-parse the BOM it just wrote.
Collectors stay independently testable, and the IR serialises to JSONL, which is what makes scans
resumable and shardable.

### Module layout

```
qdarpan/
  ir.py             CryptoFinding, AssetKind, Evidence, EvidenceTier, Location, CollectorError
  canonical.py      algorithm name canonicalisation, OID table, parameter normalisation
  collectors/
    base.py         Collector protocol, target dispatch
    source_ast.py   tree-sitter for C, C++, Java, Go
    elf.py          pyelftools: DT_NEEDED, dynsym, crypto constant search
    container.py    OCI layout / docker-save tarball / rootfs layer walk
    tls.py          live handshake, negotiated suite, cert chain, named groups
  normalise.py      canonical key -> merge, noisy-OR confidence combination
  journal.py        append-only JSONL run journal, manifest, resume
  cbom.py           IR -> cyclonedx-python-lib -> CycloneDX 1.7
  risk.py           Mosca X+Y>Z across three Z scenarios, IR 8547 deprecation clock
  recommend.py      FIPS 203/204/205 targets, hybrid TLS, size and latency deltas
  diff.py           CBOM-to-CBOM delta
  evidence.py       auditor evidence pack builder
  policy/
    pqc_policy.json         FIPS dates, IR 8547 milestones, DST FY2027-28, GRI Z range
    algorithms.json         algorithm registry: primitive, security bits, PQ status, sizes
    migration_costs.json    classical -> PQ size and latency deltas with sources
  cli.py            qdarpan scan | report | diff | evidence | serve | policy
  api.py            FastAPI over the same engine
  web/index.html    single-file dashboard, no build step
```

---

## 5. Data model

### CryptoFinding

The single currency of the system. Collectors produce it; everything downstream consumes it.

```python
@dataclass(frozen=True)
class CryptoFinding:
    target_id: str            # canonical id of the scanned thing: repo path, image ref, host:port
    asset_kind: AssetKind     # ALGORITHM | CERTIFICATE | PROTOCOL | RELATED_MATERIAL | LIBRARY
    name: str                 # canonical: "RSA-2048", "ECDSA-P256", "AES-256-GCM", "TLS1.2"
    primitive: Primitive      # pke | signature | kem | hash | block-cipher | mac | kdf | drbg
    parameters: Mapping       # key_size, curve, mode, padding, hash
    oid: str | None
    functions: frozenset[CryptoFunction]
    library: str | None       # "openssl@3.0.2"
    location: Location        # surface, path, line, offset, layer_digest, endpoint
    evidence: tuple[Evidence, ...]
    confidence: float         # 0.0 .. 1.0
    collector: str
```

### Dedupe key

```
canonical_key = (target_id, asset_kind, canonical_name, frozenset(significant_parameters))
```

`target_id` is deliberately part of the key. The same RSA-2048 in two different repos is two
findings; RSA-2048 found in one repo by both the AST collector and the ELF collector is one finding
with two evidence records. `significant_parameters` excludes cosmetic fields (source line, variable
name) and includes semantics (key size, curve, mode, padding, hash, version).

Estate-level rollup is a **view** computed over findings, never a merge that loses the per-target
attribution an auditor needs.

---

## 6. Confidence ladder

Confidence is defined, published, and testable — not a vibe.

| Tier | Meaning | Base |
|---|---|---|
| `NEGOTIATED` | Observed in a live TLS handshake. A fact, not an inference. | 0.99 |
| `DIRECT_API_CALL` | AST shows a call to a known crypto API with resolvable arguments | 0.95 |
| `LINKED_LIBRARY_PINNED` | `DT_NEEDED` / import **and** the algorithm pinned by symbol or constant | 0.80 |
| `CRYPTO_CONSTANT` | FindCrypt-style S-box, IV, or round-constant match in a binary | 0.70 |
| `LINKED_LIBRARY_UNPINNED` | Crypto library linked but the algorithm not determined | 0.55 |
| `STRING_LITERAL` | Algorithm name appears as a string in source or config | 0.40 |
| `FILENAME_METADATA` | Inferred from a filename or package name only | 0.30 |

Merged evidence combines by noisy-OR:

```
combined = min(0.99, 1 - Π(1 - cᵢ))
```

Corroboration across surfaces raises confidence without ever reaching certainty for inferred
evidence. A `NEGOTIATED` record alone already sits at the ceiling — correct, because we watched it
happen.

Findings below a configurable floor (default 0.35) are retained in the journal but excluded from
the CBOM, and surfaced under `--include-low-confidence`. The floor sits above the
`FILENAME_METADATA` base of 0.30, so filename-only inferences are journaled but never shipped in a
CBOM by default. Nothing is silently dropped.

---

## 7. Collectors

All four run over a shared worker pool sized to CPU count, stream their inputs, and honour a
per-file size cap. A collector failure never aborts a scan; it emits a `CollectorError` record and
the run exits with a partial-failure code.

### 7.1 source_ast

tree-sitter parsers for C, C++, Java, Go. C and C++ are the differentiator — `sonar-cryptography`
has no C/C++ support, and OpenSSL-consuming C is exactly what sits in Indian CII estates.

Rule packs are declarative JSON: qualified call pattern → algorithm, primitive, function, and the
argument index carrying the key size or curve. Constant folding is deliberately shallow — literal
arguments and file-local `#define` / `const` only. Anything unresolvable degrades to
`LINKED_LIBRARY_UNPINNED` rather than guessing.

Initial rule coverage: OpenSSL EVP and legacy APIs, libsodium, mbedTLS, Java JCA
(`Cipher.getInstance`, `KeyPairGenerator`, `Signature`, `MessageDigest`), Go `crypto/*`.

### 7.2 elf

`pyelftools`. Reads `DT_NEEDED` for linked crypto libraries, scans `.dynsym` for known crypto
symbol names, and searches `.rodata` for crypto constants (AES S-box, SHA round constants, MD5
sines, DES tables). Handles stripped and statically linked binaries — the constant search is the
answer to the "stripped binaries" risk in the deck.

### 7.3 container

No Docker daemon. Accepts an OCI image layout directory, a `docker save` tarball, or an extracted
rootfs. Walks layers newest-first, dedupes files by digest, runs the ELF collector over binaries,
and reads package metadata (dpkg status, apk installed, rpm) to attribute crypto libraries to
packages and versions. Layer digest is recorded in `Location`, so an auditor sees which layer
introduced a weak algorithm.

### 7.4 tls

Live handshake using the stdlib `ssl` module plus `cryptography` for certificate parsing. Records
negotiated protocol version, cipher suite, named group, and the certificate chain — signature
algorithm, key type, key size, validity window.

The only collector that opens a socket. Touches operator-supplied targets only, and is skipped
entirely under `--offline`. Concurrency and timeouts are bounded so that scanning 2,300 endpoints
does not behave like a port scanner.

---

## 8. CBOM emission

`cbom.py` maps IR findings onto `cyclonedx-python-lib` 11.11's crypto model and serialises at
`SchemaVersion.V1_7`.

| IR `asset_kind` | CycloneDX |
|---|---|
| `ALGORITHM` | `CryptoProperties(assetType=algorithm, algorithmProperties=...)` |
| `CERTIFICATE` | `CryptoProperties(assetType=certificate, certificateProperties=...)` |
| `PROTOCOL` | `CryptoProperties(assetType=protocol, protocolProperties=...)` |
| `RELATED_MATERIAL` | `CryptoProperties(assetType=related-crypto-material, ...)` |
| `LIBRARY` | ordinary `Component` of type `library`, linked by dependency |

Confidence, evidence tier, matcher id and collector id ride as namespaced `properties`
(`qdarpan:confidence`, ...) since CycloneDX has no native slot for them. The IR journal remains the
authoritative evidence record.

### Determinism

Under `--reproducible`: components sorted by bom-ref, bom-refs derived as
`sha256(canonical_key)[:16]`, serial number derived from the content hash rather than randomly, and
the timestamp taken from the newest input mtime rather than the wall clock. Two scans of unchanged
inputs produce byte-identical files, which is what makes quarter-over-quarter CBOM diffing in git
meaningful.

---

## 9. Risk engine

### Mosca inequality

`X + Y > Z`, per Mosca, IEEE S&P 16(5), 2018.

- **X** — years to migrate this asset. Defaults per asset class, overridable per target in policy.
- **Y** — years the protected data must stay confidential, from the target's criticality tier.
- **Z** — years until a cryptographically relevant quantum computer.

Z is contested, so Q-DARPAN does not invent a number. It evaluates the inequality against three
scenarios from the GRI Quantum Threat Timeline 2025 expert range — optimistic, median, pessimistic
— and reports **which of the three trip**. An asset that fails under all three is urgent; one that
fails only under the pessimistic scenario is not.

### Deprecation clock

Independent of Mosca: years remaining until NIST IR 8547 (ipd) deprecation (2030) and disallowance
(2035) for 112-bit RSA/ECC, and until the DST NQM vendor-CBOM milestone (FY 2027-28). An asset can
be low-urgency under Mosca and still be on a regulatory clock; both are reported.

Findings are tiered `CRITICAL` / `HIGH` / `MEDIUM` / `LOW` / `PQ-SAFE`, combining
quantum-vulnerability, criticality tier, Mosca scenarios tripped, and confidence.

---

## 10. Recommender

| Found | Recommendation |
|---|---|
| RSA / ECDSA / EdDSA signature | ML-DSA (FIPS 204); SLH-DSA (FIPS 205) where a stateless hash-based scheme is preferred, e.g. firmware signing |
| RSA-KEM / ECDH / DH key exchange | ML-KEM (FIPS 203); hybrid X25519MLKEM768 for TLS 1.3 per RFC 10024 |
| AES-128 | AES-256, for Grover margin |
| SHA-1, MD5 | Already classically broken — flagged separately from quantum risk |
| SHA-256, SHA-3, AES-256 | PQ-safe at current understanding; no action |

`migration_costs.json` carries byte deltas with cited sources, e.g. ML-DSA-65 public key 1952 B vs
ECDSA-P256 64 B (+1888 B), signature 3309 B vs 64 B (51.7×); ML-KEM-768 public key 1184 B and
ciphertext 1088 B vs X25519's 32 B each.

Output is a **ranked migration queue**: risk tier first, then blast radius (how many targets share
the finding), then migration cost. That ordering is the product.

---

## 11. Interfaces

### CLI

```
qdarpan scan <target>...  [--surface source,elf,container,tls] [--out DIR]
                          [--resume] [--reproducible] [--offline]
                          [--include-low-confidence] [--policy FILE]
qdarpan report <run-dir>  [--format md|json]
qdarpan diff <old.cbom.json> <new.cbom.json>
qdarpan evidence <run-dir> -o pack.zip
qdarpan serve             [--host 127.0.0.1] [--port 8787]
qdarpan policy            show | validate
```

Targets are auto-classified: a directory implies source + ELF, a `.tar` implies container, a
`host:port` implies TLS. Explicit `--surface` overrides.

### Run directory

```
<out>/runs/<run_id>/
  manifest.json       targets, content hashes, tool version, policy hash
  findings.jsonl      append-only IR journal — the evidence of record
  errors.jsonl        CollectorError records
  cbom.json           CycloneDX 1.7
  report.md
```

`--resume` reads `manifest.json`, skips targets whose content hash is unchanged, and appends.

### `qdarpan diff`

Compares two CBOMs and reports appeared / disappeared / changed crypto assets, grouped by risk
tier. Free once emission is deterministic — and for a SOC running quarterly scans, the delta *is*
the deliverable.

### Evidence pack

`qdarpan evidence` zips the journal, the policy snapshot, the tool version and commit, the
manifest and the CBOM. A regulator can reconstruct exactly how every claim was reached.

### API and dashboard

FastAPI (`api.py`) exposes the same engine: `POST /scan`, `GET /runs`, `GET /runs/{id}/cbom`,
`GET /runs/{id}/risk`, `GET /diff`. Binds `127.0.0.1` by default.

The dashboard is a single self-contained `web/index.html` — no npm, no build step, no
`node_modules`. A single file is a deliberate air-gap decision, not a shortcut.

---

## 12. Error handling

- Collectors never abort the run. Failures become `CollectorError` records with target, phase and
  reason.
- Exit codes: `0` clean, `1` usage or config error, `2` partial failure, `3` no targets resolved.
- Unparseable source files, malformed ELF, truncated tarballs and TLS timeouts are expected
  conditions with recorded outcomes, not exceptions.
- A network call attempted while `--offline` is set is a hard error, not a warning.

---

## 13. Testing

`pytest`. No network in the test suite; the TLS collector is tested against a locally spawned `ssl`
server using a self-signed certificate generated at fixture time by `cryptography`.

- **Unit** per collector against a checked-in fixture corpus: small C, C++, Java and Go files with
  known crypto calls; a small ELF; a synthetic OCI tarball assembled by a fixture.
- **Normaliser**: cross-surface merge, noisy-OR arithmetic, key collisions.
- **Emitter**: output validates against the CycloneDX 1.7 JSON schema; byte-identical output under
  `--reproducible`.
- **Risk**: Mosca scenario boundaries, deprecation-clock arithmetic.
- **Golden-file** end-to-end: fixture estate in, known CBOM out.
- **Metrics**: precision and recall per collector over the labelled corpus, written to the README.

---

## 14. Phases

| Phase | Deliverable |
|---|---|
| **1** | `ir.py`, `canonical.py`, `normalise.py`, `journal.py`, `cbom.py`, `risk.py`, `recommend.py`, `cli.py`, policy files. End-to-end on a fixture target. |
| **2** | The four collectors for real. Confidence ladder wired. Fixture corpus and per-collector metrics. |
| **3** | `diff`, evidence pack, FastAPI, single-file dashboard, vendored wheel bundle, offline-install verification. |
| **4** | Deck pass: fix ECMA-424, update the `sonar-cryptography` claim, fill team placeholders, replace the dead repo link, insert real screenshots and measured numbers. |

Each phase ends with a green test suite.

---

## 15. Repository

Apache-2.0, published at `github.com/RohanExploit/q-darpan`. The deck already cites this URL and it
currently 404s; Phase 1 makes it resolve.

README states measured coverage and measured precision/recall, and marks anything not yet built as
not yet built.
