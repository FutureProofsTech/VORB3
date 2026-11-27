# Side-Channel Measurement Report

**Status:** optimized-build checkpoint (2026-11-27). Evidence, not a formal
constant-time proof.
**Profile:** SP-288/35 baseline; the NIST-tier packs are reported in §2.5.

## 1. Scope and method

### 1.1 Timing

`tools/attack` provides two randomized-class tests:

```bash
./target/release/vorb3-attack dudect 50000          # fixed key vs second key
./target/release/vorb3-attack dudect-verify 50000   # valid vs corrupted signature
```

The harness warms both classes, selects the class with a xorshift bit (not a
fixed alternation), measures one operation with `Instant`, and reports Welch's
t. The acceptance threshold is `|t| < 4.5`.

### 1.2 Why not 50M samples

At the optimized release rates (about 7.0 ms/signature and 6.3 ms/verification),
50M samples per class would still require roughly 4 days for signing and 3.6
days for verification on one core. That is not a meaningful local gate. The campaign
uses 50,000 samples per test, which has useful power against moderate timing
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

### 1.5 Valgrind ctgrind

`scripts/ctgrind.sh` links the safe library into a C harness, marks the 36-byte
seed and 32-byte entropy as undefined, then calls key generation and signing for
eight message lengths (0 to 4096 bytes). Memcheck reports any conditional jump
or memory address that depends on those undefined bytes.

```bash
./scripts/ctgrind.sh
```

This complements dudect: ctgrind is not statistical and does not require timing
stability. It is still dynamic, so it covers only the exercised paths.

## 2. Results

### 2.1 Timing

Signing (`dudect 50000`, fixed key vs second key):

```text
n = 50,000
mean A = 6995847 ns
mean B = 6998602 ns
Welch t = -1.383
```

Verification (`dudect-verify 50000`, valid vs corrupted signature):

```text
n = 50,000
mean A = 6275957 ns
mean B = 6275605 ns
Welch t = 0.552
```

Both are below `|t| < 4.5`. The run was made on the final optimized binary after
the fuzz campaigns had stopped.

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

### 2.4 ctgrind

The raw run reports exactly four unique conditional sites, all at
`PublicKey::from_bytes` (`keys.rs:25`) via `from_secret`/`public_key` or
`public_key_from_parts`/`sign_into`. That check rejects a degenerate derived
public key. The public key is a public output (and in signing is already known
to the verifier), so this is a declassification point, not a leak of the seed:

```text
raw conditional reports: 4 total, 4 at PublicKey::from_bytes
```

With those four call stacks suppressed, Memcheck exits clean:

```text
CTGRIND PASS: no other secret-dependent branch or address
```

No secret-dependent branch or address was found in Rain, GGM, BLAKE3, the
transcript, wire filling, or proof assembly for the exercised lengths.

### 2.5 NIST-tier packs

The same randomized-class harness was run at 50,000 samples per test on the
release build of each pack:

| Pack | Sign mean (a/b) | Sign Welch t | Verify mean (a/b) | Verify Welch t |
|---|---:|---:|---:|---:|
| Level 1+ (SP-160/32) | 10,534,457 / 10,539,700 ns | -1.820 | 5,313,381 / 5,309,187 ns | 2.113 |
| Level 3+ (SP-224/32) | 16,072,904 / 16,072,739 ns | 0.026 | 5,467,552 / 5,467,535 ns | 0.012 |

All four tests are inside the `|t| < 4.5` acceptance threshold. These are
statistical measurements, not a formal constant-time proof. Selected field and
key primitives pass Miri for both packs; the Level 3+ key path is additionally
checked with strict provenance and symbolic alignment.

## 3. Interpretation limits

- dudect tests are statistical; a non-significant t does not prove
  constant-time execution.
- Cachegrind counts are deterministic for the instrumented binary, not a
  hardware side-channel measurement.
- Assembly review is manual; the audit script is a review aid, not a verifier.
- ctgrind is dynamic and path-limited; it does not prove absence of all
  secret-dependent behaviour.
- The derived-public-key degeneracy check is a documented public-value branch.
- No power/EM measurement, no formal constant-time proof, no external audit.
