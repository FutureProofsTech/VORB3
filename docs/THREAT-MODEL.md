# VORB3-SP1 — Threat Model (Phase 0)

**Status:** Draft for approval.
**Scope:** VORB3-SP1 signature library; field/tree profile pending D21 (SP-128
baseline, SP-128+ 288, recommended SP-160 320).

---

## 1. Assets

| Asset | Location | Impact if lost |
|---|---|---|
| Rain secret key `sk` | expanded secret / signer memory | universal forgery for that key |
| Compact seed | secret storage | regeneration of `sk`,`pt` |
| GGM tree seeds / leaf shares `u_i` | signer memory | witness mask recovery, potential forgery |
| VOLE tags `v_i`, wire values `w_i` | signer memory | witness disclosure |
| Mask tuple `u*,v*` | signer memory | proof leakage |
| Entropy input | caller | hedged nonce quality |
| Public key / signatures | public | integrity/authenticity |

## 2. Adversaries

1. **Network attacker:** sees public keys/signatures, can mutate, truncate,
   transplant, replay, and submit malformed inputs. Goal: forgery, malleability,
   DoS, oracle leaks.
2. **Quantum attacker:** Grover/BHT capabilities; goal: key recovery, proof
   soundness break, hash collision. Target: 128-bit quantum.
3. **Local timing/cache attacker:** observes sign latency/cache lines, injects
   faults, probes memory. Goal: recover `sk`, leaf indices, or witness.
4. **Malicious prover:** knows the protocol, tries to produce a signature for a
   key it does not own, exploit the zero selector, the VOLEitH hidden-leaf
   commitment, the mask tuple, or Fiat–Shamir grinding.
5. **Faulty RNG:** frozen/zero entropy, snapshot rollback, injected failure.
6. **Malicious key supplier:** feeds zero/degenerate/low-order public keys.
7. **Supply-chain attacker:** attempts to introduce runtime dependencies or
   build-time code. Mitigation: zero runtime deps, no build.rs.
8. **Compiler/microarchitecture:** branch synthesis, dead-store elimination,
   speculative execution. Mitigation: CT coding, black_box, assembly audit,
   documented platform limits.

## 3. Trust boundaries

- The core library trusts `core` and the caller-provided entropy bytes only.
- The caller is responsible for secure seed storage and entropy acquisition.
- The OS/hardware is trusted for basic execution, not for side-channel
  guarantees; LFENCE/speculation mitigation is a platform responsibility.
- The Python model is not trusted for timing or security; it only defines
  equations.

## 4. Attack surface

| Surface | Inputs | Required behavior |
|---|---|---|
| `PublicKey::from_bytes` | 64 B | reject pt=0/ct=0; no panic |
| `Signature::from_bytes` | 11,456 / 14,024 / 16,848 B | exact profile length; no trailing bytes |
| `verify` | msg, pk, sig | one `InvalidSignature` for content failures; fixed work |
| `sign` | msg, secret, entropy | fail closed; no partial output; wipe |
| `KeyGen` | seed/entropy | nonzero sk/pt/ct; CT zero mapping |
| Transcript | pk/salt/msg/roots | framed, domain-separated, ratcheted |
| GGM/Merkle | indices | all bounds checked; no secret indexing |
| QuickSilver | wire values/tags | batched checks; no early exit |
| Error paths | malformed inputs | no panic, no secret leak, no partial buffer |

## 5. Security goals

- SUF-CMA at 128-bit quantum / 256-bit classical.
- Key recovery at 128-bit quantum / 256-bit classical.
- Proof soundness at 128-bit quantum.
- Zero-knowledge: witness and selector bits not leaked beyond the proof.
- Constant-time signing with respect to secrets (evidence-based).
- Uniform verification failure for signature-content errors.
- No heap, no unsafe, no external runtime dependencies.
- Complete zeroization of owned secret buffers; residual-risk statement.

## 6. Non-goals

- Defending against an attacker with arbitrary read/write access to process
  memory while signing.
- A formal hardware speculation proof.
- Absolute zeroization of compiler temporaries/registers (safe Rust limits).
- External audit claims.
- Protecting against a malicious compiler/toolchain.
- Side-channel guarantees for the Python model.

## 7. Phase-0-specific risks

| Risk | Consequence | Mitigation |
|---|---|---|
| Rain-SP1 15-round security unproven | weak cipher | Phase-4 cryptanalysis; increase rounds/trees |
| Original binary MDS incompatible with compact proof | unsound if forced | field-linear Rain-SP1 (D15); no MDS in SP1 |
| WH512 combiner assumption | hash security gap | security case; SHA-512 fallback (D14) |
| VOLEitH hidden-leaf budget | circuit too large | 2-wire/round gadget; `T ≥ 2R+2`; 15 rounds baseline |
| Selector gadget implementation bug | invalid proof/forgery | model + Kani + Rust tests |
| Mask tuple misuse | ZK leak | one-time-pad mask; model check |
| Fiat–Shamir grinding | forgery | 256/288/320-bit challenge; h2 binding |
| 32 KB stack target | failure | measure; 64 KB cap; no crypto shrink |

## 8. Assumptions to be validated in later phases

- BLAKE3 is a random oracle/PRF with independent domain instances.
- WH512's two-instance concatenation has the generic 512-bit bound.
- Rain-SP1 is one-way/key-resistant at the target with enough rounds.
- VOLEitH all-but-one commitment and QuickSilver retain their standard
  soundness/ZK in this instantiation.
- Fiat–Shamir is sound in the random oracle model.
- Safe Rust + black_box + dudect/cachegrind/assembly evidence is sufficient for
  the stated side-channel claims.
