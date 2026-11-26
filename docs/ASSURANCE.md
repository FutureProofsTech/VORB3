# VORB3-SP1 — Assurance Plan (Phase 0)

**Status:** Draft for approval.
**Rule:** every claim is **proved**, **tested**, or **assumed**. No external audit
is claimed.

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
| Rain-SP1 security | cryptanalysis dossier | Z3/GP/sympy | report | G7 |
| Selector gadget | model + Kani + Rust tests | model, Kani | proof/test logs | G2 |
| GGM/Merkle binding | model + reconstruction + mutation | model/testkit | root vectors | G2 |
| Transcript domain separation | frame/replay/collision tests | testkit | test logs | G2 |
| Wire binding | byte table + mutation sweep | testkit | 91,648-bit sweep | G4 |
| SUF-CMA | cross-key/msg + fuzz | testkit/cargo-fuzz | attack logs | G4 |
| Constant-time sign | dudect 50M + cachegrind + asm | testkit/valgrind | t-test/cache logs | G3 |
| Zeroization | canary scan | testkit | scan report | G5 |
| Stack | 64 KB thread, 32 KB target | testkit/nightly | stack report | G1/G4 |
| Reproducibility | two clean builds | scripts | hash comparison | G6 |
| Cross-arch | x86_64/aarch64/ppc64/s390x | qemu | KAT report | G6 |
| Coverage | line/branch 100% target | llvm-cov/tarpaulin | coverage report | G1 |
| Mutation | kill critical mutants | cargo-mutants | mutation report | G1 |
| Fuzzing | 1B / 72h | cargo-fuzz/AFL++ | corpus/crash log | G4 |
| Formal | Kani proof inventory | Kani | proof report | G2 |
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
- **G3 Side-channel:** 50M dudect |t|<4.5; cachegrind; assembly audit.
- **G4 Fuzzing/DoS:** 1B executions / 72h; zero crashes; stack evidence;
  ASan/UBSan/Miri.
- **G5 Memory:** canary scan clean in defined region; all secret wipe paths
  tested; residual-risk statement.
- **G6 Reproducible/KAT:** two clean builds byte-identical; x86_64+aarch64 KATs;
  endian build; KAT manifest.
- **G7 Security-first:** Rain-SP1 cryptanalysis above the Level-5 target;
  union-bound table fully supported; no component below 128-bit quantum.

Every green gate requires a command, tool version, artifact/hash, and
human-readable conclusion.

---

## 4. What is not covered yet

- Rust implementation and its proofs.
- Side-channel/zeroization/stack measurements.
- Fuzz campaigns.
- Cryptanalysis of Rain-SP1.
- External review.

Phase 0 only freezes the equations and the model. It does not certify the
scheme's computational security.
