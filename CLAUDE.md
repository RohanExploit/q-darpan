# Q-DARPAN — project context

Read this first. It records the things that are not derivable from the code.

## What this is

Smart India Hackathon 2026, problem statement **SIH26164** — *Enterprise Cryptographic
Discovery & Analysis Tool (ECDAT)*, theme Blockchain & Cybersecurity, software category.
Team lead: Rohan (github.com/RohanExploit).

Q-DARPAN discovers cryptographic assets across an enterprise estate, emits a CycloneDX 1.7
CBOM, scores each asset for quantum risk with Mosca's inequality, and ranks a migration
queue toward FIPS 203/204/205. Fully on-premises: no egress, no agents, **no GPU**.

Design spec: `docs/superpowers/specs/2026-09-07-q-darpan-design.md`. Read it before
changing architecture.

## Where things live

| Thing | Path |
|---|---|
| Repo | `E:\q-darpan` |
| venv | `E:\q-darpan\.venv` (Python 3.10.0) |
| GitHub | `github.com/RohanExploit/q-darpan` — **private** |
| Scan output | `E:\q-darpan\runs\<run_id>\` (gitignored) |

**The project used to live on `R:\New folder\q darpan`. That volume dismounted mid-session
on 2026-09-07 and is not a physical partition — no `subst`, no VHD, no attached disk.
Everything was rebuilt on E:. Do not look for R:, and do not write anything to it.**

The original deck `SIH2026_SIH26164_Q-DARPAN.pptx` was lost with R:. Its full text is
reproduced in the design spec's §2 and in the deck-correction notes below; the slide
design and images are not recoverable from here.

`PIP_CACHE_DIR` is still set to the dead `R:\caches\pip` in the user's environment. Export
`PIP_CACHE_DIR=E:/caches/pip` before running pip, or it warns.

## Running it

```bash
.venv/Scripts/python.exe -m qdarpan.cli scan tests/fixtures/sample_repo --out runs
.venv/Scripts/python.exe -m qdarpan.cli scan example.com:443 --surface tls
.venv/Scripts/python.exe -m qdarpan.cli report runs/<run_id>
.venv/Scripts/python.exe -m qdarpan.cli diff old/cbom.json new/cbom.json
.venv/Scripts/python.exe -m pytest
```

Exit codes are load-bearing: `0` clean, `1` usage, `2` partial failure, `3` no targets.

## Architecture invariants

Break these and the design stops working:

1. **Collectors emit `CryptoFinding` and nothing else.** They never build CycloneDX objects
   and never raise — failures become `CollectorError` records.
2. **`target_id` is part of the dedupe key.** Same algorithm in two repos = two findings.
   Same algorithm found by two collectors in one repo = one finding, two evidence records.
3. **Confidence comes from the published tier ladder, combined by noisy-OR**
   (`1 - Π(1 - cᵢ)`, capped 0.99). Never hand-assign a score.
4. **Never invent a parameter.** A detection with no observed key size stays `RSA`, not
   `RSA-2048`. Registry `default_parameter` exists only where the standard itself names a
   parameter set (ML-KEM, ML-DSA, SLH-DSA).
5. **Determinism under `--reproducible`.** bom-refs are `sha256(canonical_key)[:16]`,
   timestamp is fixed, serial number is content-derived. This is what makes `qdarpan diff`
   meaningful quarter over quarter — do not reintroduce wall-clock or random values.
6. **Policy, the algorithm registry and detection rules are data, not code**
   (`qdarpan/policy/*.json`, `qdarpan/collectors/rules/*.json`). A reviewer must be able to
   audit coverage without reading Python.
7. **Mosca's Z is never a single number.** Evaluate against all three GRI 2025 scenarios and
   report which trip.
8. **No GPU, no ML, no `syft`, no Docker daemon, no npm.** These are deliberate rejections,
   documented in the spec's constraints table. The container collector reads tarballs and
   OCI layouts directly.

## Deck corrections — verified 2026-09-07, not yet applied to the deck

The submitted deck contains three claims that are wrong or stale. Phase 4 fixes them.

- **ECMA-424.** The deck states the mapping twice and contradicts itself. Truth: ECMA-424
  1st edition = CycloneDX v1.6 (Jun 2024); **2nd edition = CycloneDX v1.7 (Dec 2025)**.
- **sonar-cryptography.** The deck says "reads Java, Python, Go only". It gained **C#** in
  v1.7.0 (1 Sep 2026). Still **no C/C++** — the differentiator survives, the wording does not.
- **NIST IR 8547** is still an Initial Public Draft (12 Nov 2024). Say "(ipd)".

Verified and correct as written: RFC 10024 (Std Track, Aug 2026 — X25519MLKEM768,
SecP256r1MLKEM768, SecP384r1MLKEM1024; framework is RFC 9954); FIPS 203/204/205 (Aug 2024);
the ML-DSA-65 vs ECDSA-P256 figures (+1888 B public key, 51.7× signature).

Also unfixed in the deck: `<TEAM ID>`, `<TEAM NAME>` and `<TEAM>` placeholders on every
slide, and the repo link that 404s until the GitHub repo goes public.

## Style

Match the existing code. Module docstrings explain *why* the module exists, not what it
does. Comments earn their place by recording a decision or a trap, never by narrating the
next line. Data files carry a `$comment` key stating what a reviewer should check.
