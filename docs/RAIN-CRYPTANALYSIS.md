# Rain-SP1 Cryptanalysis Dossier

**Status:** local analysis checkpoint. This is **not** a proof of 128-bit
security and not an external audit.
**Profile:** SP-288/35, GF(2^288), 15 rounds, field-linear diffusion.
**Harnesses:** `scripts/rain_analysis.py`, `scripts/rain_theory.py`.

---

## 1. Design summary

Round:

```text
x_r = s_{r-1} XOR sk XOR K_r
y_r = x_r^-1            (0 -> 0)
s_r = c_r * y_r
ct  = s_{14} XOR sk
```

The only nonlinear operation is inversion in GF(2^288). The per-round
diffusion is a public scalar multiplication, which is GF(2^288)-linear and
therefore free in the QuickSilver proof. The original binary MDS layer is not
used.

The key schedule is deliberately minimal: the same 288-bit `sk` is added in
every round and once at the output; the per-round constants `K_r` and `c_r`
prevent pure slide symmetry. All 30 constants are nonzero and distinct
(measured).

## 2. Why 15 rounds

The 31-wire zero-safe selector gadget fits 32 hidden leaves at 15 rounds; the
32-tree baseline gives 256 challenge bits, and SP-288/35 gives 280. The round
count is a security-margin baseline, not a proof. If the best local attack
falls below the target, rounds and trees must increase.

## 3. Differential analysis

### 3.1 Single-round bound

For even `n`, inversion over GF(2^n) is 4-differentially uniform:

```text
max_a,b Pr[ x^-1 XOR (x XOR a)^-1 = b ] = 4 / 2^n
```

Verified exhaustively for GF(2^8): maximum count 4 out of 256
(`DP = 2^-6`), matching `4/256`.

Affine input/output maps (XOR constants and multiplication by nonzero `c_r`)
do not change the differential distribution. Each Rain round therefore has
maximum differential probability at most `4 / 2^288 = 2^-286`.

### 3.2 Full-round composition bound

For a composition of `r` functions, summing over at most `2^n` intermediate
differences gives the standard crude bound

```text
max DP(f_r o ... o f_1) <= 2^(n(r-1)) * (4 / 2^n)^r
                        =  4^r / 2^n
                        =  2^(2r - n).
```

For `n = 288`, `r = 15`:

```text
15-round differential bound <= 2^(30 - 288) = 2^-258.
```

This is far below the 128-bit target. The bound is deliberately conservative
and **weakens** as `r` grows; beyond roughly 80 rounds the crude expression
becomes vacuous. It is a valid 15-round upper bound, not a multi-round
security proof.

### 3.3 Reduced-width toy differentials

Toy Rain over GF(2^8), same round structure, random nonzero constants:

| Rounds | Max output count | Max DP | Distinct output differences |
|---:|---:|---:|---:|
| 1 | 4 | 2^-6 | 127/256 |
| 2 | 6 | 0.023438 | 126/256 |
| 3 | 6 | 0.023438 | 125/256 |
| 4 | 6 | 0.023438 | 124/256 |

The two-round value exceeds the one-round `4/256` bound because intermediate
differences may collide; it remains below the composition bound
`2^8 * (4/256)^2 = 16/256`. The toy field is only a sanity check.

## 4. Linear analysis

The inversion permutation has a large Walsh coefficient. Exhaustive FWHT for
GF(2^8) and GF(2^10) gives:

| Field | Max Walsh | Correlation |
|---|---:|---:|
| GF(2^8) | 32 | 2^-3 |
| GF(2^10) | 64 | 2^-4 |

The measured pattern is `2^(n/2 + 1) / 2^n = 2^-(n/2 - 1)` for even `n`.
For GF(2^288) this suggests a single-round correlation of at most `2^-143`,
but the multi-round correlation-matrix bound is vacuous after summing over
`2^288` intermediate masks. **No useful multi-round linear bound is claimed.**
Linear cryptanalysis remains an assumption/limitation, not a proved margin.

## 5. Algebraic analysis

Inversion has algebraic degree `n - 1 = 287`. Toy GF(2^8) degree growth,
computed with a Möbius transform over all 256 inputs:

| Rounds | Max coordinate degree |
|---:|---:|
| 1 | 7 |
| 2 | 7 |
| 3 | 7 |
| 4 | 7 |

Degree saturates immediately at the maximum `n - 1`. An interpolation attack
on the full instance needs on the order of `2^288` points; Gröbner/linearization
on a 288-bit state is far outside the local budget. This is an argument, not a
machine-checked lower bound.

## 6. Structural checks

`scripts/rain_analysis.py` runs:

- 4 random keys × 64 random plaintexts: no ciphertext collisions, no sampled
  fixed points;
- zero, one, and all-ones boundary inputs: complete without panic;
- 256 random plaintexts differing in the low bit: 256 distinct output
  differences, no repeated difference in the sample.

These are sanity checks. They do not establish permutation quality on the full
domain.

## 7. Constants

SP-288/35 constants are derived with BLAKE3 derive-key from frozen labels:

```text
15 round constants K_r + 15 diffusion constants c_r
all nonzero: yes
all distinct: yes
Hamming weight: min 127, max 159, mean 142.9 of 288 bits
```

No constant is zero, one, or a low-weight value in the tested set.

## 8. Best local assessment

- Differential: 15-round crude upper bound `2^-258`; no differential trail
  found that approaches it.
- Linear: single-round correlation `~2^-143`; multi-round bound vacuous; no
  practical trail search completed at full width.
- Algebraic: degree saturates at 287; full-width interpolation/Gröbner is
  infeasible locally, but no lower bound is proved.
- Structural: no collision, fixed-point, or low-bit differential bias in the
  samples.
- Implementation: cipher KAT matches the independent Python model; selector
  gadget is complete and sound by the four equations.
- Formal toy check: Z3 proves over GF(2^8) that the four selector equations
  have only the zero case (`b=1,x=y=0`) or the inverse case
  (`b=0,x!=0,y=x^-1`). Script: `scripts/z3_selector.py`; result: UNSAT for a
  counterexample.

No local break was found. The honest conclusion is **“no known local attack
below the 128-bit target”**, not “proved 128-bit secure.”

## 9. Limits and next work

- Full-width differential/linear trail search with SAT/SMT or MILP.
- A proper multi-round linear-hull analysis.
- Gröbner/linearization experiments on reduced-width toy instances.
- Independent cryptanalysis; none has been performed.
- The 72-hour fuzz soak remains deferred by direction; it exercises the
  signature verifier, not the cipher's key-recovery security.

Until those are done, Rain-SP1 remains a **candidate** whose 15-round margin is
supported by a conservative differential bound and local sampling, not a
security proof.
