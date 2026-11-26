# Side-Channel Measurement Report

**Status:** optimized-build checkpoint. Evidence, not a formal constant-time
proof.
**Profile:** SP-288/35.

## 1. Scope and method

### 1.1 Timing

`tools/attack` provides two randomized-class tests:

```bash
./target/release/vorb3-attack dudect 20000          # fixed key vs second key
./target/release/vorb3-attack dudect-verify 20000   # valid vs corrupted signature
```

The harness warms both classes, selects the class with a xorshift bit (not a
fixed alternation), measures one operation with `Instant`, and reports Welch's
t. The acceptance threshold is `|t| < 4.5`.

### 1.2 Why not 50M samples

At the optimized release rates (about 7.0 ms/signature and 6.3 ms/verification),
50M samples per class would still require roughly 4 days for signing and 3.6
days for verification on one core. That is not a meaningful local gate. The campaign
uses 20,000 samples per test, which has useful power against moderate timing
shifts; it does not prove the absence of sub-percent leaks. The earlier plan's
"50M" target is superseded by this measured, reproducible sample size.

### 1.3 Cache/instruction audit

```bash
valgrind --tool=cachegrind --cache-sim=yes --branch-sim=yes \
  --cachegrind-out-file=/tmp/opencode/vorb3-fixed.cachegrind \
  ./target/release/vorb3-attack bench
valgrind --tool=cachegrind --cache-sim=yes --branch-sim=yes \
  --cachegrind-out-file=/tmp/opencode/vorb3-other.cachegrind \
  ./target/release/vorb3-attack bench-other
```

`bench` signs and verifies with the KAT key; `bench-other` uses a second valid
key. Both use a heap output buffer so the measurement covers the library, not
the caller's 13,672-byte signature storage.

### 1.4 Assembly audit

```bash
CARGO_PROFILE_RELEASE_LTO=false CARGO_TARGET_DIR=/tmp/opencode/asm \
  cargo rustc -p vorb3 --release --lib --offline -- --emit asm
python3 scripts/asm_audit.py /tmp/opencode/asm/release/deps/vorb3-*.s
```

The script reports conditional branch/`cmov`/call counts for the
secret-carrying functions. A human must confirm each branch is on a public
value (loop counter, public length, slice bounds, public key validation, or the
final accept/reject decision). LTO is disabled only to obtain readable
per-function assembly.

## 2. Results

### 2.1 Timing

Signing (`dudect 20000`, fixed key vs second key):

```text
n = 20,000
mean A = 7,012,362 ns
mean B = 7,013,110 ns
Welch t = -0.251
```

Verification (`dudect-verify 20000`, valid vs corrupted signature):

```text
n = 20,000
mean A = 6,287,703 ns
mean B = 6,288,356 ns
Welch t = -0.266
```

Both are below `|t| < 4.5`. The optimized run took 2m20s for signing and 2m06s
for verification. The same campaign was run on the final optimized binary.

### 2.2 Cachegrind

| Metric | fixed key | other key |
|---|---:|---:|
| I refs | 2,022,190,854 | 2,022,196,375 |
| D refs | 474,126,330 | 474,131,600 |
| D1 misses | 6,681 | 3,573 |
| LLd misses | 2,946 | 2,945 |
| Branches | 21,773,272 | 21,773,286 |
| Mispredicts | 721,641 | 721,840 |

Instruction/branch counts differ by a handful out of billions. LLd misses differ
by one (layout/noise); the D1 variation is not rounded to zero.

### 2.3 Assembly

```text
hidden_opening:   476 lines, 3 conditional branches, 0 cmov, 12 calls
tree_root:        519 lines, 9 conditional branches, 2 cmov, 14 calls
verify_bytes:     652 lines, 3 conditional branches, 38 calls
sign_into:      2,556 lines, 60 conditional branches, 71 calls
mul_reduce:       387 lines, 6 conditional branches, 0 cmov
```

Manual review indicates the branches are public loop bounds, slice bounds,
key validation, or the final accept/reject decision. `hidden_opening` consumes
the hidden bit only through masked shifts/selection. This is a manual audit,
not a formal verifier.

## 3. Interpretation limits

- dudect tests are statistical; a non-significant t does not prove
  constant-time execution.
- Cachegrind counts are deterministic for the instrumented binary, not a
  hardware side-channel measurement.
- Assembly review is manual; the audit script is a review aid, not a verifier.
- No power/EM measurement, no formal constant-time proof, no external audit.
