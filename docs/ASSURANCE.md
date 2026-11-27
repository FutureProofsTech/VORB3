# VORB3-SP1 — Assurance Plan

**Status:** Phase 7 local checkpoint + extended red-team campaign (2026-11-27).
**Rule:** every claim is **proved**, **tested**, or **assumed**. No external audit
is claimed.

Phase 7 evidence is in `docs/PHASE1-7-REPORT.md`,
`docs/PHASE7-ATTACK-REPORT.md`, `docs/SIDE-CHANNEL.md`,
`docs/RAIN-CRYPTANALYSIS.md`, and `docs/REDTEAM-CAMPAIGN.md`. The implementation is complete and locally
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
| Wire binding | byte table + mutation sweep | testkit | 109,376-bit sweep | G4 |
| SUF-CMA | cross-key/msg + fuzz | testkit/cargo-fuzz | attack logs | G4 |
| Constant-time sign | dudect sign/verify + ctgrind + cachegrind + asm | attack/valgrind | t-test/cache/asm/ctgrind logs | G3 |
| Zeroization | canary scan + explicit wipe tests | testkit | scan/wipe report | G5 |
| Stack | 32 KB per-op release on x86_64/aarch64/s390x/i686/ppc64/Windows/WASI; 64 KB full call | testkit/qemu/Wine | stack report | G1/G4 |
| Reproducibility | two clean builds | scripts | hash comparison | G6 |
| Cross-arch | x86_64/aarch64/s390x/i686/ppc64/Windows runtime; Apple build; WASI runtime | qemu/Wine/wasmtime | KAT report | G6 |
| Coverage | 100% functions; 99.90% lines | llvm-cov | coverage report | G1 |
| Mutation | 494 mutants, 371 caught, 27 Z3-checked equivalents + 3 unobservable `Drop`, 84 unviable, 9 timeouts | cargo-mutants/Z3 | mutation report | G1 |
| Fuzzing | 77.8M + 327.7M extended (405.6M total); 72h deferred | cargo-fuzz/AFL++ | corpus/crash log | G4 |
| Formal | 18 Kani helpers; full sign/verify open | Kani | proof report | G2 |
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
| Field polynomial | SymPy irreducible over GF(2); `scripts/verify_poly.py` |
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
- **G3 Side-channel:** randomized dudect for sign and verify with |t|<4.5;
  Valgrind ctgrind for keygen/sign; cachegrind; assembly audit. The 50M target
  is superseded as impractical at measured release speeds (D22).
- **G4 Fuzzing/DoS:** 77.8M executions in the 10-minute six-target campaign,
  plus an extended 1-hour campaign (327,716,350 executions; 405,581,569 total), zero crashes; 1B/72h deferred by direction;
  stack evidence; Miri.
- **G5 Memory:** ASan, Miri, memcheck, and careful-mode clean; canary scan in
  defined region; all secret wipe paths tested; residual-risk statement.
- **G6 Reproducible/KAT:** two clean builds byte-identical; x86_64/aarch64/
  s390x/i686 runtime KATs; big-endian s390x; WASI graph; KAT manifest.
- **G7 Security-first:** Rain-SP1 cryptanalysis above the Level-5 target;
  union-bound table fully supported; no component below 128-bit quantum.

Every green gate requires a command, tool version, artifact/hash, and
human-readable conclusion.

---

## 3.1 Phase 7 evidence snapshot

| Area | Status at checkpoint |
|---|---|
| Rust implementation + KAT | implemented; byte-identical to Python model |
| 32 KiB per-operation stack | met in release on x86_64, aarch64, s390x, i686, ppc64, Windows, WASI |
| 64 KiB full sign call with stack output | met |
| 109,376 single-bit signature sweep | met, zero accepted |
| Canary + secret-fragment scan | met |
| 10-minute fuzz campaign | met, 77.8M executions, no crashes |
| Extended 1-hour fuzz campaign | met, 327,716,350 executions (405,581,569 total), zero crashes |
| 72-hour / 1B fuzz | **deferred by direction** |
| Kani helper proofs | 18/18 pass |
| Full symbolic Kani sign/verify | **not tractable; open limitation** |
| Miri full sign+verify KAT, CT/zeroization/profile/BLAKE3/field/keys/signature | pass |
| Cross-architecture runtime | aarch64 + s390x (big-endian) + ppc64 (big-endian) + i686 + Windows full graph; WASI functional + 32 KiB stack |
| Mutation | 494 mutants: 371 caught, 27 Z3-checked equivalents + 3 unobservable `Drop`, 84 unviable, 9 timeouts |
| Coverage | 100% functions, 99.90% lines (all features) |
| ctgrind | only the public-key degeneracy check depends on secret-derived data; suppressed check leaves zero |
| Reproducible rlib | `60e98d9c…` twice |
| dudect sign/verify, cachegrind, assembly | local evidence; see side-channel report |
| Rain-SP1 dossier | local analysis complete; no proof |
| External audit | **none** |

## 3.2 NIST-tier pack evidence

| Check | Level 1+ (SP-160/32) | Level 3+ (SP-224/32) |
|---|---|---|
| Model KAT + 28-case differential | pass | pass |
| Field differential (4,096 records) | pass | pass |
| Polynomial irreducibility (SymPy) | pass | pass |
| Structured envelope attacks | pass | pass |
| Single-bit sweep | 63,808 rejected | 82,368 rejected |
| Kani | 16/16 | 16/16 |
| Miri selected primitives | field + keys pass | field + keys pass |
| Dudect (50k) | sign t=-1.820, verify t=2.113 | sign t=0.026, verify t=0.012 |
| ASan full graph | pass | pass |
| Coverage | 100% funcs / 99.70% lines | 100% funcs / 99.70% lines |
| 300 s libFuzzer | 7,260,135 execs, 0 crashes | 18,848,000 execs, 0 crashes |
| 32 KiB release stack | pass | pass |
| Reproducible rlib | `15a140a6…8cac36` | `80589137…ab5fa` |
| Cross-runtime | AArch64/s390x/i686/ppc64/Windows/WASI pass | AArch64/s390x/i686/ppc64/Windows/WASI pass |
| Targeted mutation | 403: 316 caught, 24 missed, 53 unviable, 10 timeouts | 403: 316 caught, 24 missed, 53 unviable, 10 timeouts |

The `+` labels are conservative margins over NIST Level 1 (64q/128c) and
Level 3 (96q/192c); the parameter definitions are in `NIST-PACKS.md`.

## 4. What is not covered yet

- A full symbolic Kani proof of sign/verify for any profile; the NIST packs
  have helper-level Kani proofs only.
- A formal multi-round linear/algebraic security proof for Rain-SP1.
- 72-hour / 1-billion-execution fuzzing.
- External review.

This plan freezes the equations and records local evidence. It does not certify
the scheme's computational security.
