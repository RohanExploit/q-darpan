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
| Repo (**primary**) | `R:\New folder\q darpan` |
| venv | `.venv` in the repo root (Python 3.10.0) |
| GitHub | `github.com/RohanExploit/q-darpan` — **public**, and the only copy not on a disk in this machine |
| Scan output | `runs\<run_id>\` under the repo (gitignored) |
| Fallback mirror | `E:\q-darpan` — full copy, refreshed by hand. Not authoritative, do not edit. |
| Pre-outage snapshot | `.stale-20260907\` — kept so nothing was deleted. Safe to remove. |

### The drive history, and why it changes how you work

On 2026-09-07 the R: volume **dismounted mid-session and vanished from Windows entirely** —
no partition, no `subst` mapping, no mounted VHD; only the NVMe (C:, E:) and an SD card (D:)
remained. The project was rebuilt on `E:\q-darpan` and pushed to GitHub. R: later came back
and the user chose it as primary again.

**R: is primary, but it has failed once with no explanation. Every commit gets pushed.**

A `post-commit` hook does this automatically. It lives at `tools/hooks/post-commit` and is
installed with `sh tools/install-hooks.sh` (hooks are not version-controlled, so a fresh
clone needs this once). The hook is deliberately non-fatal — being offline must not make a
good commit look failed — so **if you see `post-commit: push failed`, the work exists on one
disk only. Say so out loud rather than letting it pass.**

The deck `SIH2026_SIH26164_Q-DARPAN.pptx` is tracked at `deck/` for the same reason: it was
briefly presumed lost with the volume, and a file that only exists on one disk is not safe.

`PIP_CACHE_DIR` points at `R:\caches\pip`, which works again now that R: is back.

## Running it

```bash
sh tools/install-hooks.sh          # once per clone: enables auto-push on commit

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

Two more that the first end-to-end run taught us, and that are easy to regress:

9. **Libraries are inventory, not algorithm instances.** A `crypto/md5` import or a linked
   `libcrypto` stays out of the migration queue; the real call sites are already counted.
10. **A Grover-weakened family at or above 128-bit quantum security is safe.** AES-256 must
    never appear in the queue being told to migrate to AES-256.

## Deck corrections — verified 2026-09-07, applied

The deck contained three claims that were wrong or stale. All three are fixed in
`deck/SIH2026_SIH26164_Q-DARPAN.pptx`; they are recorded here so nobody reintroduces them.

- **ECMA-424.** The deck states the mapping twice and contradicts itself. Truth: ECMA-424
  1st edition = CycloneDX v1.6 (Jun 2024); **2nd edition = CycloneDX v1.7 (Dec 2025)**.
- **sonar-cryptography.** The deck says "reads Java, Python, Go only". It gained **C#** in
  v1.7.0 (1 Sep 2026). Still **no C/C++** — the differentiator survives, the wording does not.
- **NIST IR 8547** is still an Initial Public Draft (12 Nov 2024). Say "(ipd)".

Verified and correct as written: RFC 10024 (Std Track, Aug 2026 — X25519MLKEM768,
SecP256r1MLKEM768, SecP384r1MLKEM1024; framework is RFC 9954); FIPS 203/204/205 (Aug 2024);
the ML-DSA-65 vs ECDSA-P256 figures (+1888 B public key, 51.7× signature — the tool now
reproduces the 51.7× from `migration_costs.json` rather than asserting it).

The deck was also rewritten against the official NTRO problem statement so every clause it
lists is represented; an audit script in the commit history checks 21 of 21.

Still open: the `<TEAM ID>`, `<TEAM NAME>` and `<TEAM>` placeholders. Those are registered on
the SIH portal and only the team can supply them — **do not invent values for them.**

## Traps

**`tree-sitter` is pinned `<0.26` and must stay there.** 0.26.0 corrupts the CPython heap on
this platform: after roughly six collector runs in one process, unrelated `os.stat` calls
start raising `TypeError: an integer is required` or dying with a Windows access violation,
and the visible symptom lands somewhere innocent -- a segfault in pytest's cache writer, an
`IndexError` deep inside `sortedcontainers`. It was bisected to the tree-sitter version alone;
0.25.2 is clean under an identical workload. If you widen that bound, run `tests/test_api.py`
in a loop, because that is the suite that surfaced it.

Symptoms that look like a flaky disk or a bad drive may be this instead. Check the pin before
blaming hardware.

## Style

Match the existing code. Module docstrings explain *why* the module exists, not what it
does. Comments earn their place by recording a decision or a trap, never by narrating the
next line. Data files carry a `$comment` key stating what a reviewer should check.
