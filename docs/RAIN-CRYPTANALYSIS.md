# Rain-SP1 Cryptanalysis Dossier (Phase 7 Draft)

**Status:** local analysis in progress. This is not a proof of 128-bit security.
**Profile:** SP-288/35, 15 rounds, field-linear diffusion.

---

## 1. Design summary

Round:

```
x_r = s_{r-1} XOR sk XOR K_r
y_r = x_r^-1            (0 -> 0)
s_r = c_r * y_r
ct  = s_{14} XOR sk
```

The only nonlinear operation is inversion in GF(2^288). The per-round
diffusion is a public scalar multiplication, which is GF(2^288)-linear and
therefore free in the QuickSilver proof. The original binary MDS layer is not
used.

## 2. Why 15 rounds

The 31-wire zero-safe selector gadget fits 32 hidden leaves at 15 rounds; the
32-tree baseline gives 256 challenge bits. The round count is a security-margin
baseline, not a claim. If the best local attack falls below the target, rounds
and trees must increase.

## 3. Local analysis plan

1. **Structural**
   - fixed points/cycles for random keys/plaintexts;
   - permutation/distinctness tests;
   - zero/boundary states;
   - inversion selector completeness/soundness;
   - invariant-subspace/linear-structure probes.
2. **Differential/linear**
   - reduced-round differential and linear trail search with Z3/SAT;
   - full-round sampling for obvious biases;
   - branch-number/linear-layer analysis.
3. **Algebraic**
   - interpolation degree for reduced rounds;
   - Gröbner/linearization attempts on reduced-width toy fields;
   - key-recovery complexity estimates.
4. **Implementation**
   - KAT/differential over the actual constants;
   - no evidence of a break in the tested samples.

## 4. Current evidence

- Full cipher KAT matches the independent Python model.
- Zero-state selector test passes.
- The 109,376 single-bit signature sweep and structural negative tests pass
  (signature layer, not the cipher).
- Rain analysis harness: `scripts/rain_analysis.py`.
- Ran analysis: 4 keys × 64 plaintexts distinct; zero/boundary probes complete;
  256 random LSB differential pairs produced 256 distinct output differences
  with no repeat bias. This is sanity checking, not a break or a proof.
- No local cryptanalytic break found in the sampled tests.

## 5. Limits

Local tests cannot prove that Rain-SP1 has 128-bit security. They can find
mistakes and obvious structural weaknesses; a novel cipher requires a sustained
cryptanalytic effort. The release report will state the best known local attack
and the remaining margin, not "proved secure".

## 6. Status

Run:

```bash
python3 scripts/rain_analysis.py
```

Results are appended after the 1-hour fuzz campaign completes.
