# VORB3-SP1 — Technical Specification (Phase 0 Draft)

**Status:** **FROZEN PROFILE — SP-288/35** (D21 accepted 2026-11-26). Phase 0 specification; production crate starts at Phase 1.
**Profile:** GF(2^288), 35 trees, 15 rounds, 13,672-byte signature.
**Security target:** 128-bit quantum / 256-bit classical floor; conservative ~140-bit quantum for this profile.
**Reference model:** `model/vorb3_model.py` (toy, 256, 288, 320 profiles).
**No production code is authorized until this specification and D15–D21 are signed off.**

> **F-33 / D21 parameter warning.** The 256-bit profile is ~125-bit quantum under
> the conservative 60-gate QuickSilver bound. It must not be frozen with a
> 128-bit claim. **D21 selected SP-288/35: GF(2^288), 35 trees, 13,672-byte
> signature, ~140-bit quantum floor.** **SP-288/33** (12,968 B, ~132) is the
> smallest true-128+ profile; **SP-320/40** (16,848 B, ~156.5) is maximum margin.
> The equations are shared; only the field/tree/seed/signature sizes change.
> The 256-bit format below is the equation baseline.

Supersedes: the original 128-bit / 4-round / binary-MDS / 5,712-byte sketch.

---

## 1. Scope and design decisions

VORB3-SP1 is a VOLEitH/QuickSilver signature scheme over Rain-SP1, a 256-bit
inversion-based one-way function with **field-linear diffusion**.

Three Phase-0 decisions change the original project document:

1. **F-25 — Linear layer.** A 256×256 binary MDS matrix is not
   GF(2^256)-linear. In a field-VOLE/QuickSilver proof the verifier cannot apply
   it to its MAC shares, so the compact proof cannot soundly treat the linear
   layer as free. VORB3-SP1 replaces the binary MDS with multiplication by a
   public nonzero field constant \(c_r\) per round. This is GF(2^256)-linear and
   therefore free in the proof. The cipher's diffusion now relies on the
   inversion and the per-round scalar; the round count is raised and the cipher
   is subject to the Phase-4 cryptanalysis gate. See §4 and §13.

2. **F-26 — Hidden-leaf budget.** In an all-but-one GGM vector commitment the
   verifier learns all opened leaves; only the 32 hidden leaves (one per tree)
   are secret VOLE correlations. The circuit may therefore use at most 32 secret
   wires (31 witness wires + 1 mask). VORB3-SP1 uses a zero-safe inversion gadget
   with only two secret wires per round (`y_r`, `b_r`) plus `sk`: 15 rounds gives
   31 wires, plus one mask leaf = 32. This is why the profile is
   **15 rounds with \(T \ge 32\)**; the final tree count is D21.

3. **F-27/F-28/F-29 — Wire format.** The original `d`, `w_corrections`,
   `batched_round_proof`, and an implicit `w*` cannot carry the full QuickSilver
   proof. VORB3-SP1 uses a 31-entry `wire_d` vector, a batched proof
   `(U,V)`, a public-output tag, and derives the mask verifier share from
   the dedicated mask leaf's commitment. The signature is profile-sized:
   11,456 B (256 baseline), 14,024 B (288), 16,848 B (320). The original
   5,712-byte layout is not used.

The original Rain-128, 4-round, binary-MDS, 5,712-byte design is retained only
as historical input. It is not the target.

---

## 2. Notation and parameters

| Symbol | Value |
|---|---|
| Field | \(F = GF(2^{256})\) |
| Polynomial | \(p(x)=x^{256}+x^{10}+x^5+x^2+1\) (low mask `0x425`) |
| Field encoding | 32-byte little-endian, all bit patterns canonical |
| \(R\) | 15 rounds (baseline; Phase-4 may increase) |
| GGM trees | \(T=32\) |
| Tree depth | \(D=8\), 256 leaves/tree |
| Hidden leaves | one per tree, \(T=32\) |
| Secret wires | \(2R+1=31\) |
| Mask tree | index 31 |
| Challenge | 256 bits = 32 leaf indices × 8 bits |
| Hash binding | WH512, 64-byte output |
| Salt | 64 bytes |
| Signature | 11,456 bytes |
| Public key | 64 bytes = pt 32 || ct 32 |
| Compact secret | 32-byte seed |
| Expanded secret | 96 bytes = sk 32 || pt 32 || seed 32 |
| Security target | 128-bit quantum / 256-bit classical |

### 2.1 Profile parameterization (D21)

| Profile | Field | Trees | Challenge | Seed/leaf | Field elem | Signature | Conservative quantum |
|---|---|---:|---:|---:|---:|---:|---:|
| SP-128 (baseline) | 2^256 (0x425) | 32 | 256 | 32 B | 32 B | 11,456 B | ~125 |
| SP-288/33 | 2^288 (0xC03) | 33 | 264 | 36 B | 36 B | 12,968 B | ~132 |
| **SP-288/35 (selected)** | 2^288 (0xC03) | 35 | 280 | 36 B | 36 B | **13,672 B** | **~140** |
| SP-288/36 | 2^288 (0xC03) | 36 | 288 | 36 B | 36 B | 14,024 B | ~140.5 |
| SP-320/36 | 2^320 (0x1B) | 36 | 288 | 40 B | 40 B | 15,312 B | ~144 |
| SP-320/40 (max margin) | 2^320 (0x1B) | 40 | 320 | 40 B | 40 B | 16,848 B | ~156.5 |
| SP-160/32 (NIST L1+) | 2^160 (0x2D) | 32 | 256 | 20 B | 20 B | 7,976 B | ~76.5 |
| SP-224/32 (NIST L3+) | 2^224 (0x309) | 32 | 256 | 28 B | 28 B | 10,296 B | ~108.5 |

Public key = 2×field bytes; compact seed = field bytes; expanded secret =
3×field bytes. GGM seed/leaf share = field bytes; Merkle hash = 64 B; salt/h2 =
64 B. The equations are identical; only sizes/counts change. The 256-bit
numbers in the rest of this draft are the equation baseline. A profile change
requires re-issuing every offset/size and all KATs.

**Reading note:** every “32-byte field element” and “32-byte seed” below is the
256-bit baseline. For 288/320 replace it with `F_bytes` and use the profile
table. The wire table in §9 lists all three signature sizes.

The polynomial was verified irreducible locally by two independent methods
(PARI/GP `polisirreducible` and a Python Rabin test) during planning. Phase 0
must repeat both and record the evidence before freeze.

All field addition is bitwise XOR. Multiplication is GF(2^256) multiplication.
`a^{-1}` means the field inverse with `0^{-1}=0`.

---

## 3. Hash and KDF primitives

### 3.1 BLAKE3

Implement full BLAKE3: hash, keyed hash, derive-key, XOF, streaming, arbitrary
input length, no heap. BLAKE3-256's internal chaining state is 256 bits; a longer
XOF output does **not** give 128-bit quantum collision resistance by itself.

### 3.2 WH512

`WH512(data) = BLAKE3-256(derive_key, context="VORB3-WH512-A-V1", data) ||
              BLAKE3-256(derive_key, context="VORB3-WH512-B-V1", data)`

- Output: 64 bytes.
- Two independent domain-separated BLAKE3-256 derivations.
- Generic 512-bit collision bound: 256-bit classical / ~170-bit quantum under
  the independent-domain-instance assumption. The security case must defend
  this combiner; SHA-512 is the fallback (D14).
- Used for: salt, h2, leaf commitments, Merkle nodes, Merkle roots, public-key
  hash, and the 512-bit transcript state/ratchet.

### 3.3 KDF

- `KDF_fbytes(context, data)`: BLAKE3 derive-key, `F_bytes`-byte output
  (32/36/40 for the 256/288/320 profiles).
- `KDF32(context, data)`: 32-byte output (256/32-bit profiles).
- `KDF64(context, data)`: 64-byte output.
- Contexts are the exact ASCII strings in §12; no context is reused with
  different parameters.
- Secret field material is mapped to nonzero with constant-time select: if the
  decoded field element is zero, replace it with 1. The bias is \(2^{-256}\).

### 3.4 Transcript

State: 64 bytes, initialized to `WH512("VORB3-TRANSCRIPT-INIT-V1")`.

Absorb:
```
frame = u64le(len(label)) || label || u64le(len(data)) || data
state = WH512("VORB3-TRANSCRIPT-ABSORB-V1" || state || frame)
```

Squeeze:
```
out = WH512("VORB3-TRANSCRIPT-SQUEEZE-V1" || state ||
            u64le(len(label)) || label || u64le(n))[:n]
state = WH512("VORB3-TRANSCRIPT-RATCHET-V1" || state || u64le(n) || out)
return out
```

The 512-bit state avoids the 256-bit-ratchet collision cap. Every absorb is
length-framed; every squeeze ratchets and the previous state is wiped.

Transcript schedule for signing/verification:

```
absorb "PK"    pk (64 bytes)
absorb "SALT"  salt (64)
absorb "MSG"   message (arbitrary, framed)
absorb "ROOTS" root[0] || ... || root[31]   (32 × 64 = 2048 bytes)
delta = squeeze "DELTA" 32 -> nonzero field element
chi   = squeeze "CHI"   32 -> nonzero field element
h2    = squeeze "H2"    64
```

`h2[j]` for `j=0..31` gives the hidden leaf index `alpha_j` in tree `j`
(0..255). The remaining 32 bytes of h2 bind the transcript and are checked in
full. The wire openings, `(U,V)`, and `out_tag` are responses and are **not**
absorbed before h2.

---

## 4. Rain-SP1

### 4.1 Constants

```
tag  = "VORB3-RAIN{F}-SP" with F in {256,288,320}
seed = ASCII tag || "-CONSTANTS-V1"
for r = 0..14:
    K_r = nonzero(field_from_bytes(KDF_fbytes(tag || "-K{r}-V1", seed)))
    c_r = nonzero(field_from_bytes(KDF_fbytes(tag || "-C{r}-V1", seed)))
```

`K_r` is the round key constant; `c_r` is the nonzero field-linear diffusion
constant. Both are public, deterministically regenerated, and checked in the
constant test. `c_r` is also tested for a documented low-weight branch-number
lower bound and for invertibility (nonzero over a field is sufficient).

### 4.2 Encryption

Input: secret key \(sk\in F\setminus\{0\}\), plaintext \(pt\in F\setminus\{0\}\).

```
s = pt
for r = 0..14:
    x_r = s XOR sk XOR K_r
    y_r = inv(x_r)                 # 0 -> 0
    s   = c_r * y_r
ct = s XOR sk
```

Return `(pt, ct)` as the 64-byte public key, and the witness
`(x_r, y_r, b_r, s_r)` where \(b_r=1\) iff \(x_r=0\), else 0.

### 4.3 Zero-safe inversion gadget

For every round, the proof uses the secret bit \(b_r\) and enforces:

```
b_r * b_r       = b_r
b_r * x_r       = 0
b_r * y_r       = 0
x_r * y_r       = 1 XOR b_r
```

Completeness: if \(x=0\), set \(b=1,y=0\); all four hold. If \(x\neq0\), set
\(b=0,y=x^{-1}\); all four hold.

Soundness: \(b\in\{0,1\}\). If \(b=1\), then \(b x=0\Rightarrow x=0\) and
\(b y=0\Rightarrow y=0\). If \(b=0\), then \(x y=1\Rightarrow x\neq0\) and
\(y=x^{-1}\). The two cases are exhaustive. This replaces the cubic relation
\(x^2y\oplus x=0\), which does not force \(y=0\) at \(x=0\).

The selector bit is a secret witness and is masked by the proof; it does not
leak whether an intermediate state is zero.

### 4.4 Cipher status

Rain-SP1 is a **new cipher variant**, not the original Rain-128 with a binary MDS
layer. The 15-round count is the security-margin baseline and the maximum that
fits the 32-tree / 31-wire layout. The Phase-4 cryptanalysis dossier must show
that the best local attack is above the Level-5 target. If more rounds are
required, the tree count must rise (`T >= 2R+2`) and the signature size/version
changes; rounds may never be reduced below the target.

---

## 5. Keys, entropy, and hedged signing

### 5.1 Key generation

Input: 32-byte seed.

```
sk = nonzero(field_from_bytes(KDF_fbytes("VORB3-KEYGEN-SK-V1", seed)))
pt = nonzero(field_from_bytes(KDF_fbytes("VORB3-KEYGEN-PT-V1", seed)))
ct = Rain-SP1(sk, pt)
pk = pt_bytes || ct_bytes
```

Reject sk=0, pt=0, ct=0 at the API boundary. Expanded secret:
`sk (32) || pt (32) || seed (32)`, zeroized on drop.

### 5.2 Entropy

`no_std` core has no OS RNG. The caller supplies 32 bytes through a fallible
`EntropySource`. Failure returns `RngFailure` and produces no output. All-zero
entropy is a test mode. Distinct messages produce distinct trees; the same
message and same entropy are deterministic. This is documented, not hidden.

### 5.3 Hedged master seed

```
master = KDF_fbytes("VORB3-HEDGED-V1",
                    sk_bytes || pk || u64le(len(msg)) || msg || entropy32)
salt   = WH512("VORB3-SALT-V1" || master)
```

The message length is framed to prevent boundary ambiguity. The master seed is
zeroized after the signature.

---

## 6. GGM + Merkle commitment

### 6.1 Tree roots

For tree `j = 0..31`:

```
root_seed[j] = KDF_fbytes("VORB3-TREE-ROOT-V1", master || u16le(j))
```

### 6.2 GGM expansion

Node seed is `F_bytes` (32/36/40 for the 256/288/320 profiles). For a node at level `l` and index `i`:

```
children = BLAKE3_derive_key(
    context = "VORB3-GGM-EXPAND-V1",
    data    = "VORB3-GGM-EXPAND-V1" || salt || pk_hash ||
              u16le(j) || u8(l) || u16le(i) || parent_seed,
    length  = 64)
left = children[0:seed_len]
right = children[seed_len:2*seed_len]
```

Level 0 is the root; level 8 is the leaves. All indices are in range by
construction. The expansion is a length-doubling PRG; the tree root and seeds
are secret.

### 6.3 Leaf share and commitment

Leaf seed is `F_bytes`. The leaf share is a field element:

```
u_i = nonzero(field_from_bytes(leaf_seed))
com_i = WH512("VORB3-GGM-LEAF-V1" || salt || pk_hash ||
              u16le(j) || u16le(i) || u_bytes(u_i))
```

- `u_i` is the prover's VOLE share.
- `com_i` is 64 bytes; its first `F_bytes` are the verifier's VOLE share
  \(q_i = field_from_bytes(com_i[0:F_bytes])\).
- The public key hash is `pk_hash = WH512("VORB3-PK-HASH-V1" || pk)`.
- Zero leaf seeds are mapped to 1 in constant time; the commitment binds the
  mapped value. This is required so a zero mask cannot reveal a wire.

### 6.4 Merkle nodes and root

For an internal node at level `l` (0=root, 7=children of leaves):

```
node_hash = WH512("VORB3-GGM-NODE-V1" || salt || pk_hash ||
                  u16le(j) || u8(l) || u16le(i) || left_hash || right_hash)
```

Leaf node hash is `com_i` at level 8. The root is the level-0 node hash (64
bytes). All leaves are hashed; the root commits to the whole tree.

### 6.5 Copath

For hidden index `alpha_j`, the copath is the eight sibling **seeds**:

```
for level = 8 down to 1:
    node_idx = alpha_j >> (8 - level)
    sib_idx  = node_idx XOR 1
    append levels[level][sib_idx]      # 32 bytes
```

Order in the signature: level 8 sibling first, then level 7, ..., level 1.

The verifier reconstructs the root from the hidden leaf commitment `com` and
the copath: each sibling seed expands to its subtree, whose leaf commitments
and internal hashes give the sibling node hash; combine bottom-up with the
hidden leaf hash. This is defined exactly in `model/vorb3_model.py` and must be
mirrored in the Rust verifier.

---

## 7. VOLE correlation and wire assignment

### 7.1 Correlation

For a hidden leaf of tree `j`:

```
u = hidden leaf share (prover)
q = field_from_bytes(com[0:F_bytes]) (verifier)
v = q XOR u * delta (prover)
```

The verifier's MAC relation after the wire opening `d = u XOR w` is:

```
q' = q XOR d * delta = v XOR w * delta
```

The verifier knows `q,d,delta,q'`; the prover knows `u,v,w`. The witness `w` is
hidden by the one-time pad `u`; `v` is random.

### 7.2 Fixed wire map

| Wire | Tree | Meaning |
|---:|---:|---|
| 0 | 0 | sk |
| 1..15 | 1..15 | y_0..y_14 (inversion outputs) |
| 16..30 | 16..30 | b_0..b_14 (zero selectors) |
| — | 31 | mask tuple (u*,v*) |

`wire_d[0..30]` in the signature has 31 entries, one per wire, in this order.
The hidden leaf commitment of tree `i` is `hidden_coms[i]`; `q_i` is its first
32 bytes. The mask's verifier share is `q* = hidden_coms[31][0:F_bytes]`.

### 7.3 Wire values and tags

Secret wire values and prover tags:

```
w_sk = sk
w_y[r] = y_r
w_b[r] = b_r
q_sk, v_sk from tree 0
q_y[r], v_y[r] from tree 1+r
q_b[r], v_b[r] from tree 16+r
```

Public/linear wires (verifier share `q`, prover tag `v`, value `w`):

```
pt:      w = pt,        q = pt*delta,   v = 0
0:       w = 0,         q = 0,          v = 0
1:       w = 1,         q = delta,      v = 0
K_r:     w = K_r,       q = K_r*delta,  v = 0
x_r:     w = s_{r-1} XOR sk XOR K_r,
         q = q_s XOR q_sk XOR K_r*delta,
         v = v_s XOR v_sk
s_r:     w = c_r*y_r,
         q = c_r*q_y[r],
         v = c_r*v_y[r]
1 XOR b: w = 1 XOR b,   q = delta XOR q_b,  v = v_b
```

The initial `s_0 = pt` has `q = pt*delta, v = 0`. The final public ciphertext
`ct = s_15 XOR sk` has `q_ct = q_s XOR q_sk`, `v_ct = v_s XOR v_sk`; the prover
sends `v_ct` as `out_tag`, and the verifier checks
`q_ct == v_ct XOR ct*delta`.

---

## 8. QuickSilver proof

### 8.1 Gates

Per round, in this order:

1. \(b_r \cdot b_r = b_r\)
2. \(b_r \cdot x_r = 0\)
3. \(b_r \cdot y_r = 0\)
4. \(x_r \cdot y_r = 1 \oplus b_r\)

For each gate \((a,b,c)\), the prover computes:

```
A0 = v_a * v_b
A1 = w_a * v_b XOR w_b * v_a XOR v_c
```

The verifier computes:

```
B = q_a * q_b XOR q_c * delta
```

If the gate is correct, \(B = A0 \oplus A1\cdot\delta\).

### 8.2 Batching

Let `chi` be the transcript challenge and `G=60` gates for 15 rounds. The prover
computes:

```
A0 = XOR_{i=0..G-1} A0_i * chi^i
A1 = XOR_{i=0..G-1} A1_i * chi^i
```

The verifier computes:

```
B = XOR_{i=0..G-1} B_i * chi^i
```

### 8.3 Zero-knowledge mask

The mask leaf (tree 31) gives `(u*,v*)` with verifier share
`q* = hidden_coms[31][0:F_bytes]`:

```
v* = q* XOR u* * delta
U = A0 XOR v*
V = A1 XOR u*
```

The prover sends `(U,V)`. The verifier checks:

```
B XOR q* == U XOR V * delta
```

This is a one-time-pad mask: the verifier knows `q*` but not `u*,v*`.

### 8.4 Public output

The prover sends `out_tag = v_ct`. The verifier recomputes `q_ct` from the
linear wires and checks:

```
q_ct == out_tag XOR ct * delta
```

### 8.5 Soundness sketch

For a wrong multiplication gate, \(B \oplus A0 \oplus A1\delta\) is a nonzero
polynomial in \(\delta\) of degree at most 2; batching with a random `chi` makes
it nonzero with overwhelming probability. The selector constraints force
\(y=\mathrm{inv}(x)\) for every round. The output tag forces the public
ciphertext. The VOLEitH all-but-one commitment binds the hidden leaf values
under the WH512 collision assumption; the Fiat–Shamir transcript binds the
roots and the indices. A full error budget is in `docs/SECURITY-CASE.md`.

---

## 9. Signature wire format — frozen SP-288/35

All field elements are 36-byte little-endian. Hashes/roots are raw 64 bytes.
Seeds are 36 bytes. The signature is exactly **13,672 bytes**.

| Offset | Length | Field |
|---:|---:|---|
| 0 | 64 | salt |
| 64 | 64 | h2 |
| 128 | 31×36 = 1,116 | wire_d (sk, y_0..y_14, b_0..b_14) |
| 1,244 | 36 | U |
| 1,280 | 36 | V |
| 1,316 | 36 | out_tag |
| 1,352 | 35×8×36 = 10,080 | copaths |
| 11,432 | 35×64 = 2,240 | hidden_coms |
| 13,672 | — | end |

Any other length is rejected. There are no trailing bytes, no variable-length
fields, and no non-canonical field encodings (every 36-byte string is a field
element).

Profile sizes (historical/alternative; the frozen profile is 288/35):

| Profile | wire_d | U,V | out_tag | copaths | hidden_coms | total |
|---|---:|---:|---:|---:|---:|---:|
| 256 / 32 | 992 | 64 | 32 | 8,192 | 2,048 | 11,456 |
| 288 / 33 | 1,116 | 72 | 36 | 9,504 | 2,112 | 12,968 |
| **288 / 35** | **1,116** | **72** | **36** | **10,080** | **2,240** | **13,672** |
| 288 / 36 | 1,116 | 72 | 36 | 10,368 | 2,304 | 14,024 |
| 320 / 36 | 1,240 | 80 | 40 | 11,520 | 2,304 | 15,312 |
| 320 / 40 | 1,240 | 80 | 40 | 12,800 | 2,560 | 16,848 |

Deserialization order is strictly the 288/35 table order. Copath order is per
§6.5; hidden_coms order is tree 0..34. Wires use trees 0..30; tree 31 is the
mask; trees 32..34 are unused challenge trees but remain committed and bound by
the roots/h2.

The h2 first 35 bytes are the hidden indices (280 challenge bits); bytes 35..63
bind the transcript and are checked in full.

---

## 10. Sign algorithm

Input: message `msg`, expanded secret, 32-byte entropy, public key derived from
the secret.

1. Validate `sk != 0`, `pt != 0`, `ct != 0`.
2. Compute `pk_hash = WH512("VORB3-PK-HASH-V1" || pk)`.
3. Compute `master` and `salt` per §5.3.
4. Pass A: for each tree `j=0..34`, derive `root_seed`, expand the GGM tree,
   compute leaf shares/commitments and the Merkle root. Store 35 roots.
5. Transcript: absorb PK, SALT, MSG, ROOTS; squeeze DELTA (36), CHI (36), H2
   (64). Map DELTA/CHI zero to 1.
6. Compute `alpha_j = h2[j]` for each tree.
7. Pass B: re-expand each tree; extract the copath for `alpha_j`; compute
   `com_j`, `u_j`, `q_j`; store them. The mask is tree 31.
8. Compute the Rain-SP1 witness `(x_r,y_r,b_r,s_r)` and `ct`.
9. Build the 31 secret wires; `d_i = u_i XOR w_i`; compute `q_i'` and `v_i`;
   verify the MAC relation in debug/tests.
10. Compute the 60 gate `(A0_i,A1_i)` values, batch with `chi`, and compute
    `(U,V)` with the mask leaf.
11. Compute `out_tag = v_ct`.
12. Serialize the signature; wipe master, tree seeds, leaf seeds, `u`, `v`,
    witness, and intermediates on every exit.

Two-pass signing avoids storing 35 full trees; the verifier is streaming.

## 11. Verify algorithm

Input: message, public key, signature bytes.

1. Reject wrong length and `pt=0` or `ct=0`.
2. Read salt/h2; compute `alpha_j = h2[j]`.
3. For each of the 35 trees, reconstruct the Merkle root from
   `hidden_coms[j]` and `copaths[j]`; store 35 roots.
4. Recompute the transcript with PK, SALT, MSG, ROOTS; squeeze DELTA, CHI, H2'.
   Check `H2' == h2` in constant time.
5. Map DELTA/CHI zero to 1.
6. Recompute `q_i' = q_i XOR d_i*delta` for the 31 wires; `q_i` is the first
   36 bytes of the hidden commitment.
7. Recompute `q` for every linear wire and every gate `B_i`; batch with
   `chi` powers.
8. Check `B XOR q* == U XOR V*delta`.
9. Recompute `q_ct`; check `q_ct == out_tag XOR ct*delta`.
10. Accumulate all checks into a single valid flag; return one
    `InvalidSignature` for any signature-content failure. No early exit based
    on signature content. Key validity is checked separately.

The verifier does not re-expand the hidden leaf's subtree (it cannot); the
Merkle root binds the hidden commitment. The verifier does expand every opened
sibling subtree to reconstruct the root.

---

## 12. Domain label registry

KDF/BLAKE3 contexts:

```
VORB3-WH512-A-V1
VORB3-WH512-B-V1
VORB3-GGM-EXPAND-V1
VORB3-KEYGEN-SK-V1
VORB3-KEYGEN-PT-V1
VORB3-HEDGED-V1
VORB3-PK-HASH-V1
VORB3-TREE-ROOT-V1
VORB3-RAIN{256|288|320}-SP-CONSTANTS-V1
VORB3-RAIN{256|288|320}-SP-K{r}-V1
VORB3-RAIN{256|288|320}-SP-C{r}-V1
```

WH512 domain prefixes in data:

```
VORB3-SALT-V1
VORB3-PK-HASH-V1
VORB3-GGM-LEAF-V1
VORB3-GGM-NODE-V1
VORB3-TRANSCRIPT-INIT-V1
VORB3-TRANSCRIPT-ABSORB-V1
VORB3-TRANSCRIPT-SQUEEZE-V1
VORB3-TRANSCRIPT-RATCHET-V1
```

Transcript labels:

```
PK, SALT, MSG, ROOTS, DELTA, CHI, H2
```

No label may be reused with different parameters. A label change is a protocol
version change.

---

## 13. Security claims, assumptions, and non-goals

### Target

- 128-bit quantum / 256-bit classical floor: key recovery, SUF-CMA, proof
  soundness.
- WH512 collision: 256-bit classical / ~170-bit quantum under the independent
  BLAKE3-domain assumption.
- **Frozen field/profile: GF(2^288), 35 trees, 15 rounds.**
  - field-check quantum ≈140.5
  - tree challenge 280 bits → 140 quantum
  - key 288 bits → 144 quantum
  - WH512 ≈170 quantum
  - **overall conservative floor ≈140**
- The union bound is computed in `docs/SECURITY-CASE.md`; any component below
  128-bit quantum is a release blocker.

### Assumptions

- Rain-SP1 with 15+ rounds resists key recovery and algebraic/differential/
  linear attacks at the target. **This is not proved; it is the Phase-4
  cryptanalysis gate.**
- BLAKE3 behaves as a random oracle/PRF with independent domain instances.
- WH512's two-instance concatenation has the generic 512-bit collision bound.
- The VOLEitH all-but-one commitment and QuickSilver proof retain their
  standard soundness/ZK properties in this instantiation.
- Fiat–Shamir in the random oracle model; the implementation is correct and
  constant-time where required.

### Non-goals / limitations

- This is not an external audit.
- No machine-checked proof of computational 128-bit security.
- No production crypto implementation, side-channel measurement, or fuzz
  campaign yet; Phase 1 is the repository/toolchain skeleton only.
- The model is Python and tests completeness/equations, not timing or memory.
- The original binary-MDS Rain is not implemented in this profile.
- Higher-than-Level-5 profiles are out of scope for SP1.

---

## 14. Versioning

- This document: `VORB3-SP1-FROZEN-288/35-2026-11-26`.
- Any change to field, polynomial, rounds, tree count, wire map, hash, transcript,
  labels, or signature layout increments the spec version and invalidates all
  KATs.
- The model and future Rust implementation must carry the same version and KAT
  manifest.

---

## 15. Reference model status

`model/vorb3_model.py` implements this specification and passes:

- Toy profile: 32-bit field, 4 trees, depth 3, 1 round, 4 gates, 456-byte
  signature; valid/mutations rejected.
- 256 equations baseline: 256-bit field, 32 trees, 11,456-byte signature.
- **Frozen SP-288/35: 288-bit field, 35 trees, depth 8, 15 rounds, 60 gates,
  13,672-byte signature; valid/mutations/transplants rejected.**
- Alternatives tested: 288/33, 288/36, 320/36, 320/40.

The model is an independent executable specification, not a security proof.
