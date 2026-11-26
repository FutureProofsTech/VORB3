# VORB3-SP1 — Wire Binding Table (Frozen SP-288/35)

**Profile:** GF(2^288), 35 trees, depth 8, 15 rounds.
**Signature length:** **13,672 bytes.**
**Encoding:** field elements 36-byte little-endian; hashes/roots 64 bytes; seeds
36 bytes; no variable-length fields; no trailing bytes.

Every signature byte must be bound by a transcript absorption, Merkle root
reconstruction, VOLE MAC/wire equation, the QuickSilver mask check, or the
public-output check. There are no padding/unbound bytes.

---

## 1. Top-level layout

| Offset | Length | Field | Bound by |
|---:|---:|---|---|
| 0 | 64 | `salt` | transcript `SALT`; GGM/leaf/node hashes |
| 64 | 64 | `h2` | recomputed transcript; 35 leaf indices; all 64 bytes checked |
| 128 | 1,116 | `wire_d[31]` (31×36) | wire MACs; verifier computes `q_i' = q_i XOR d_i·delta` |
| 1,244 | 36 | `U` | mask check `B XOR q* == U XOR V·delta` |
| 1,280 | 36 | `V` | same mask check |
| 1,316 | 36 | `out_tag` | public `ct` MAC check |
| 1,352 | 10,080 | `copaths[35][8]` (35×8×36) | Merkle root reconstruction |
| 11,432 | 2,240 | `hidden_coms[35]` (35×64) | roots, `q_i`, `q*` |
| 13,672 | — | end | exact length required |

---

## 2. `wire_d` sub-layout

31 entries, 36 bytes each:

| Index | Tree | Wire | Role |
|---:|---:|---|---|
| 0 | 0 | `sk` | secret key mask |
| 1..15 | 1..15 | `y_0..y_14` | inversion outputs |
| 16..30 | 16..30 | `b_0..b_14` | zero selectors |

Tree 31 is the mask leaf and has **no** `wire_d` entry. Trees 32..34 are unused
challenge trees but remain committed.

For each wire:

```
u_i  = hidden leaf share of tree i
q_i  = field_from_bytes(hidden_coms[i][0:36])
d_i  = wire_d[i]
v_i  = q_i XOR u_i * delta        (prover)
q_i' = q_i XOR d_i * delta        (verifier)
check: q_i' == v_i XOR w_i * delta
```

The verifier never learns `u_i,v_i,w_i`. The model asserts every relation.

---

## 3. Copath sub-layout

For each tree `j = 0..34`, eight 36-byte sibling seeds:

```
copaths[j][0] = level 8 sibling (leaf sibling)
copaths[j][1] = level 7 sibling
...
copaths[j][7] = level 1 sibling
```

For `alpha_j = h2[j]`:

```
node_idx = alpha_j >> (8 - level)
sib_idx  = node_idx XOR 1
```

The verifier expands each sibling subtree, hashes leaves/nodes, and combines
with the hidden commitment to obtain the tree root. The 35 roots are absorbed
into the transcript; `h2` is checked in full. Every copath byte is therefore
bound.

---

## 4. `hidden_coms` sub-layout

For each tree `j`, 64 bytes:

```
hidden_coms[j] = WH512("VORB3-GGM-LEAF-V1" || salt || pk_hash ||
                       u16le(j) || u16le(alpha_j) || u_bytes(u_j))
```

Bound by:

- Merkle leaf hash / root reconstruction (all 64 bytes);
- transcript `ROOTS` absorption / h2 check;
- `q_j = first 36 bytes` in the VOLE/wire equations;
- tree 31's first 36 bytes = `q*` in the mask check.

---

## 5. Public key/message binding

| Input | Bound by |
|---|---|
| `pk` (72 B = pt 36 || ct 36) | transcript `PK`; `pk_hash` in every GGM/leaf/node hash |
| `msg` | transcript `MSG`, length-framed |
| `salt` | transcript; GGM/leaf/node |
| `h2` | transcript check; 35 indices; roots |
| `delta` | transcript squeeze; every MAC equation |
| `chi` | transcript squeeze; batching powers |
| `out_tag` | public `ct` check |
| `U,V` | QuickSilver mask check |

Key validation: reject `sk=0`, `pt=0`, `ct=0`. `pt=ct` and nonzero low-order
elements are not auto-rejected.

---

## 6. Equation coverage

Every signature byte maps to:

1. transcript absorption (salt, h2, roots);
2. Merkle root reconstruction (copaths, hidden_coms);
3. VOLE MAC/wire equation (`wire_d`, first 36 bytes of hidden_coms);
4. QuickSilver mask check (`U,V`, tree-31 `q*`);
5. public output check (`out_tag`, public `ct`).

No reserved/padding bytes.

---

## 7. Tests that enforce this table

- Exact length 13,672; reject 13,671/13,673/truncated/trailing.
- Offset asserts for every boundary.
- Single-bit flip over all 109,376 bits; every mutation must fail.
- Each `wire_d`, `U`, `V`, `out_tag`, one copath byte, one hidden_com byte.
- Cross-tree transplants of `wire_d`, hidden_coms, copaths.
- h2 index mutation; salt/pk/msg substitution.
- Root reconstruction vs full tree for every tree in the model.
