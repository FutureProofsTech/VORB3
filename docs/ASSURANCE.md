# VORB3-SP1 — Assurance Plan

**Status:** Phase 7 local checkpoint (2026-11-26).
**Rule:** every claim is **proved**, **tested**, or **assumed**. No external audit
is claimed.

Phase 7 evidence is in `docs/PHASE1-7-REPORT.md`,
`docs/PHASE7-ATTACK-REPORT.md`, `docs/SIDE-CHANNEL.md`, and
`docs/RAIN-CRYPTANALYSIS.md`. The implementation is complete and locally
exercised; the security case remains a candidate case.

---

## 1. Requirement → evidence matrix

| Requirement | Method | Tool | Evidence artifact | Gate |
|---|---|---|---|---|
| No `unsafe` | `forbid(unsafe_code)` | rustc/clippy | build log | G1 |
| No std/alloc/runtime deps | no_std, empty graph | cargo, `cargo tree` | dependency proof | G1 |
| No panic/unwrap/indexing | lints + Kani + fuzz | clippy, Kani, cargo-fuzz | proof/logs | G1/G2/G4 |
| Field correctness | independent model + KAT + Kani | model, Kani | differential logs | G2 |
| WH512/BLAKE3 correctness | official KAT + b3sum/py-blake3 | scripts | KAT manifest | G6 |
| Rain-SP1 correctness | model + KAT | model | vectors | G2 |
| Rain-SP1 security | local dossier; no proof | Python | report | G7 |
| Selector gadget | model + Kani + Rust tests | model, Kani | proof/test logs | G2 |
| GGM/Merkle binding | model + reconstruction + mutation | model/testkit | root vectors | G2 |
| Transcript domain separation | frame/replay/collision tests | testkit | test logs | G2 |
| Wire binding | byte table + mutation sweep | testkit | 91,648-bit sweep | G4 |
| SUF-CMA | cross-key/msg + fuzz | testkit/cargo-fuzz | attack logs | G4 |
| Constant-time sign | dudect 20k sign + 20k verify + cachegrind + asm | attack/valgrind | t-test/cache/asm logs | G3 |
| Zeroization | canary scan + explicit wipe tests | testkit | scan/wipe report | G5 |
| Stack | 32 KB per-op release; 64 KB full call | testkit/nightly | stack report | G1/G4 |
| Reproducibility | two clean builds | scripts | hash comparison | G6 |
| Cross-arch | x86_64/aarch64/ppc64/s390x | qemu | KAT report | G6 |
| Coverage | line/branch 100% target | llvm-cov/tarpaulin | coverage report | G1 |
| Mutation | kill critical mutants | cargo-mutants | mutation report | G1 |
| Fuzzing | 1h checkpoint; 72h deferred | cargo-fuzz | corpus/crash log | G4 |
| Formal | 6 Kani helpers; full sign/verify open | Kani | proof report | G2 |
| Malicious prover | algebraic model + reduced Kani/Z3 | model/Kani/Z3 | soundness report | G2 |
| Spec conformance | byte binding + KAT | docs/testkit | manifest | G6 |

---

## 2. Phase 0 evidence

| Item | Evidence |
|---|---|
| Full-size models | `model/vorb3_model.py --all`: 256/288/320 profiles verify |
| Toy model | `model/vorb3_model.py`: 792-byte signature verifies |
| Mutation sample | model rejects sampled mutations/messages/keys |
| Root reconstruction | model asserts prover root == verifier root |
| Wire/equation consistency | model asserts every wire/gate/mask/output relation |
| Field polynomial | GP + Python Rabin (planning); must repeat before freeze |
| KAT digests | `docs/PHASE0-REPORT.md` §5 |
| Wire binding | `docs/WIRE-BINDING.md` |
| Threat model | `docs/THREAT-MODEL.md` |
| Security case | `docs/SECURITY-CASE.md` |
| Decisions | `docs/DECISIONS.md` |

The model is **not** a security proof and does not test timing/memory.

---

## 3. Gate definitions

- **G1 Compiler/linter:** no_std, no unsafe, zero warnings, clippy denies, fmt,
  empty runtime dependency graph, coverage/mutation targets.
- **G2 Formal/algebraic:** Kani proof inventory; reduced-model algebraic proofs;
  soundness model; explicit assumptions; no false "proved" label.
- **G3 Side-channel:** 20k-sample randomized dudect for sign and verify with
  |t|<4.5; cachegrind; assembly audit. The 50M target is superseded as
  impractical at measured release speeds (D22).
- **G4 Fuzzing/DoS:** 1-hour checkpoint with zero crashes (207,402 executions);
  1B/72h deferred by direction; stack evidence; Miri.
- **G5 Memory:** canary scan clean in defined region; all secret wipe paths
  tested; residual-risk statement.
- **G6 Reproducible/KAT:** two clean builds byte-identical; x86_64+aarch64 KATs;
  endian build; KAT manifest.
- **G7 Security-first:** Rain-SP1 cryptanalysis above the Level-5 target;
  union-bound table fully supported; no component below 128-bit quantum.

Every green gate requires a command, tool version, artifact/hash, and
human-readable conclusion.

---

## 3.1 Phase 7 evidence snapshot

| Area | Status at checkpoint |
|---|---|
| Rust implementation + KAT | implemented; byte-identical to Python model |
| 32 KiB per-operation stack | met in release (`sign_into`, `verify_bytes`) |
| 64 KiB full sign call with stack output | met |
| 109,376 single-bit signature sweep | met, zero accepted |
| Canary + secret-fragment scan | met |
| 1-hour fuzz | met, 207,402 executions, no crashes |
| 72-hour / 1B fuzz | **deferred by direction** |
| Kani helper proofs | 6/6 pass |
| Full symbolic Kani sign/verify | **not tractable; open limitation** |
| Miri CT/zeroization/short BLAKE3 | pass |
| dudect sign/verify, cachegrind, assembly | local evidence; see side-channel report |
| Rain-SP1 dossier | local analysis complete; no proof |
| External audit | **none** |

## 4. What is not covered yet

- A full symbolic Kani proof of the 288-bit, 15-round, 35-tree sign/verify.
- A formal multi-round linear/algebraic security proof for Rain-SP1.
- 72-hour / 1-billion-execution fuzzing.
- Cross-architecture KATs, reproducible-build comparison, coverage/mutation
  scores.
- External review.

This plan freezes the equations and records local evidence. It does not certify
the scheme's computational security.
