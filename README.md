# Q-DARPAN

Enterprise cryptographic discovery, CycloneDX 1.7 CBOM generation, and post-quantum risk
analysis. Built for Smart India Hackathon 2026, problem statement **SIH26164** — *Enterprise
Cryptographic Discovery & Analysis Tool (ECDAT)*.

Runs entirely on-premises. No network egress, no agents, no cloud upload, **no GPU**.

---

## What it does

```
targets ──┬─> source AST (C, C++, Java, Go)  ─┐
          ├─> ELF binaries                   ─┤
          ├─> container images               ─┼─> normalise ─┬─> CycloneDX 1.7 CBOM
          └─> live TLS endpoints             ─┘  (dedupe +   ├─> Mosca risk bands
                                                 confidence) └─> ranked migration queue
```

Four collectors emit one neutral finding type. A normaliser merges what they saw of the same
asset and combines their confidence. One emitter produces the CBOM; the risk engine and the
recommender read the findings directly.

## Why not just use CBOMkit?

| | CBOMkit / sonar-cryptography | Q-DARPAN |
|---|---|---|
| Source languages | Java, Python, Go, C# (as of v1.7.0, Sep 2026) | **C, C++**, Java, Go |
| Binaries | — | ELF linkage, symbols, FindCrypt constants |
| Containers | — | OCI layouts and `docker save` tarballs, no daemon |
| Live TLS | — | handshake, cipher suite, certificate, group probing |
| Risk model | — | Mosca `X+Y>Z` across three CRQC scenarios |
| Recommendation | — | FIPS 203/204/205 targets with byte-level cost |
| Quarterly delta | — | `qdarpan diff` between two CBOMs |

C and C++ are the gap that matters: OpenSSL-consuming C is what sits underneath most Indian
CII estates, and no open-source CBOM tool reads it today.

## Install

```bash
python -m venv .venv
.venv/Scripts/python.exe -m pip install -e ".[api,dev]"
sh tools/install-hooks.sh   # optional: push every commit to origin automatically
```

Requires Python 3.10+. Roughly 15 MB of new dependencies: `tree-sitter` plus four grammar
wheels, and `pyelftools`.

Air-gapped install:

```bash
pip download -d vendor/wheels -e .
pip install --no-index --find-links vendor/wheels qdarpan
```

## Use

```bash
qdarpan scan ./repo ./bin/daemon image.tar example.com:443 --out runs
qdarpan scan ./estate --offline --reproducible      # no sockets, byte-identical output
qdarpan scan ./estate --resume                      # skip targets whose content is unchanged
qdarpan report runs/<run_id> --format md
qdarpan diff q1/cbom.json q2/cbom.json              # what changed since last quarter
qdarpan evidence runs/<run_id> -o pack.zip          # auditor evidence pack
qdarpan policy validate
```

Exit codes: `0` clean · `1` usage error · `2` partial failure · `3` no targets resolved.

Each run directory holds `findings.jsonl` (the evidence of record, including findings below
the confidence floor), `manifest.json`, `cbom.json`, `report.md` and `report.json`.

## Confidence is published, not asserted

Every finding carries an evidence tier, and merging combines them by noisy-OR
(`1 − Π(1 − cᵢ)`, capped at 0.99):

| Tier | Meaning | Base |
|---|---|---|
| `NEGOTIATED` | observed in a live TLS handshake | 0.99 |
| `DIRECT_API_CALL` | AST call site with resolvable arguments | 0.95 |
| `LINKED_LIBRARY_PINNED` | linkage plus a pinned algorithm | 0.80 |
| `CRYPTO_CONSTANT` | FindCrypt-style table match in a binary | 0.70 |
| `LINKED_LIBRARY_UNPINNED` | crypto library linked, algorithm unknown | 0.55 |
| `STRING_LITERAL` | algorithm name in source or config | 0.40 |
| `FILENAME_METADATA` | inferred from a package or filename | 0.30 |

Findings below 0.35 are journaled but kept out of the CBOM unless you pass
`--include-low-confidence`. Nothing is silently dropped, and nothing is silently invented: a
detection with no observed key size stays `RSA`, never `RSA-2048`.

## Risk: two clocks, not one

**Mosca's inequality** (`X + Y > Z`, IEEE S&P 16(5), 2018) asks whether migration time plus
data shelf life already exceeds the time to a cryptographically relevant quantum computer.
Z is genuinely contested, so Q-DARPAN evaluates all three ends of the Global Risk Institute
2025 expert range and reports which trip:

```
RSA-2048  X=3y + Y=15y   optimistic  (Z=20y): holds, margin +2y
                          median      (Z=14y): TRIPS, margin -4y
                          pessimistic (Z=9y):  TRIPS, margin -9y
```

**The regulatory clock** runs separately: NIST IR 8547 (ipd) deprecates 112-bit RSA/ECC after
2030 and disallows it after 2035; the DST National Quantum Mission expects vendor CBOMs from
FY 2027-28. An asset can be calm under Mosca and still be on a deadline.

## Recommendations carry their cost

| Found | Target | Wire cost |
|---|---|---|
| ECDSA-P-256 signature | ML-DSA-65 (FIPS 204) | signature 64 B → 3309 B (**51.7×**) |
| RSA-2048 signature | ML-DSA-65 (FIPS 204) | signature 256 B → 3309 B (12.9×) |
| ECDH / X25519 | ML-KEM-768 (FIPS 203), hybrid X25519MLKEM768 per RFC 10024 | ciphertext 32 B → 1088 B |
| AES-128 | AES-256 | Grover leaves AES-128 at 64-bit quantum security |

The queue is ordered by risk tier, then blast radius, then cost. That ordering is the product.

## Determinism

Under `--reproducible`, bom-refs are `sha256(canonical_key)[:16]`, the serial number is
content-derived and the timestamp is fixed. Two scans of unchanged inputs produce
byte-identical CBOMs, which is what makes quarter-over-quarter diffing in git meaningful.

## Status

Alpha. 123 tests pass, covering canonicalisation across ecosystem spellings, cross-surface
merging, all four collectors against real inputs (a hand-built ELF, a synthetic `docker save`
tarball, a loopback TLS server), CBOM emission and determinism, the risk model's scenario
boundaries, the CLI end to end, and the HTTP service behind the dashboard.

Not yet built: the HSM (PKCS#11) and cloud KMS collectors, per-collector precision/recall over
a labelled corpus, and the vendored offline wheel bundle. See
`docs/superpowers/specs/2026-09-07-q-darpan-design.md`.

### Dashboard

```bash
qdarpan serve            # http://127.0.0.1:8787
```

One self-contained HTML file: no npm, no bundler, no CDN, no web fonts. It renders the ranked
queue, per-finding evidence, the three Mosca scenarios and the recommendation with its byte
costs, and it can launch a scan. A test asserts the page contains no outbound URL at all,
because an enclave that resolves nothing still has to render the whole UI.

## References

- CycloneDX v1.7 = **ECMA-424 2nd edition** (Dec 2025); v1.6 was the 1st edition (Jun 2024)
- FIPS 203 (ML-KEM), FIPS 204 (ML-DSA), FIPS 205 (SLH-DSA) — NIST, Aug 2024
- NIST IR 8547 *Transition to Post-Quantum Cryptography Standards* — initial public draft, Nov 2024
- RFC 10024, *PQ/T Hybrid Key Agreement Mechanisms for TLS 1.3* — Aug 2026 (framework: RFC 9954)
- Mosca, *Cybersecurity in an era with quantum computers* — IEEE S&P 16(5), 2018
- Global Risk Institute, *Quantum Threat Timeline Report 2025*
- DST National Quantum Mission, Quantum Safe Ecosystem Task Force report, 4 Feb 2026

## Licence

Apache-2.0.
