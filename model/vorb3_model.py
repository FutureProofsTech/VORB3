#!/usr/bin/env python3
"""
VORB3 Phase-0 independent reference model.

Purpose
-------
This is a *specification model*, not production code. It implements the
VORB3-SP1 equations from docs/VORB3-SPEC-1.md so that completeness and the
byte/equation bindings can be exercised before the Rust crate exists.

Independence
------------
- Python big integers for GF(2^bits).
- py-blake3 for BLAKE3 (independent of the future Rust implementation).
- No code shared with the production crate.

The model deliberately supports a small "toy" parameter set for fast protocol
tests and the full SP-128 parameter set for KAT-sized checks.
"""

from __future__ import annotations

import argparse
import dataclasses
import hashlib
import os
import sys
from typing import Dict, List, Optional, Sequence, Tuple

import blake3


# ---------------------------------------------------------------------------
# Parameters
# ---------------------------------------------------------------------------


@dataclasses.dataclass(frozen=True)
class Params:
    bits: int
    poly: int
    trees: int
    depth: int
    rounds: int

    def __post_init__(self) -> None:
        if self.bits % 8 != 0:
            raise ValueError("field bits must be a multiple of 8")
        if self.trees < 2 * self.rounds + 2:
            raise ValueError("this model requires trees >= 2*rounds + 2")
        if self.depth < 1 or self.depth > 8:
            raise ValueError("depth must be in 1..8")
        if self.poly.bit_length() - 1 != self.bits:
            raise ValueError("polynomial degree must equal field bits")

    @property
    def fbytes(self) -> int:
        return self.bits // 8

    @property
    def leaves(self) -> int:
        return 1 << self.depth

    @property
    def secret_wires(self) -> int:
        return 2 * self.rounds + 1

    @property
    def mask_tree(self) -> int:
        return 2 * self.rounds + 1

    @property
    def salt_len(self) -> int:
        return 64

    @property
    def h2_len(self) -> int:
        return 64

    @property
    def com_len(self) -> int:
        return 64

    @property
    def seed_len(self) -> int:
        return self.fbytes

    def sig_len(self) -> int:
        return (
            self.salt_len
            + self.h2_len
            + self.secret_wires * self.fbytes
            + 2 * self.fbytes
            + self.fbytes
            + self.trees * self.depth * self.seed_len
            + self.trees * self.com_len
        )


TOY = Params(bits=32, poly=0x10000008D, trees=4, depth=3, rounds=1)
FULL = Params(bits=256, poly=0x10000000000000000000000000000000000000000000000000000000000000425,
              trees=32, depth=8, rounds=15)
# SP-128+ candidate: 288-bit field, 36 trees, same 15 rounds/31 wires.
SP288 = Params(
    bits=288,
    poly=(1 << 288) | (1 << 11) | (1 << 10) | (1 << 1) | 1,
    trees=36,
    depth=8,
    rounds=15,
)
# SP-128+ tested variants: 288-bit field, 33/35/36 trees.
SP288_33 = Params(bits=288, poly=SP288.poly, trees=33, depth=8, rounds=15)
SP288_35 = Params(bits=288, poly=SP288.poly, trees=35, depth=8, rounds=15)
# SP-160 tested variants: 320-bit field, 36/40 trees.
SP320_36 = Params(
    bits=320,
    poly=(1 << 320) | (1 << 4) | (1 << 3) | (1 << 1) | 1,
    trees=36,
    depth=8,
    rounds=15,
)
SP160 = Params(
    bits=320,
    poly=(1 << 320) | (1 << 4) | (1 << 3) | (1 << 1) | 1,
    trees=40,
    depth=8,
    rounds=15,
)


# ---------------------------------------------------------------------------
# GF(2^bits)
# ---------------------------------------------------------------------------


def _deg(x: int) -> int:
    return x.bit_length() - 1


def _clmul(a: int, b: int) -> int:
    r = 0
    while b:
        if b & 1:
            r ^= a
        b >>= 1
        a <<= 1
    return r


def _reduce(x: int, p: Params) -> int:
    for i in range(2 * p.bits - 2, p.bits - 1, -1):
        if (x >> i) & 1:
            x ^= p.poly << (i - p.bits)
    return x


def gf_mul(a: int, b: int, p: Params) -> int:
    return _reduce(_clmul(a, b), p)


def gf_sq(a: int, p: Params) -> int:
    return gf_mul(a, a, p)


def gf_pow(a: int, e: int, p: Params) -> int:
    r = 1
    while e:
        if e & 1:
            r = gf_mul(r, a, p)
        a = gf_sq(a, p)
        e >>= 1
    return r


def gf_inv(a: int, p: Params) -> int:
    # a^(2^bits - 2), with 0 -> 0 by exponentiation.
    return gf_pow(a, (1 << p.bits) - 2, p)


def gf_from_bytes(b: bytes, p: Optional[Params] = None) -> int:
    v = int.from_bytes(b, "little")
    if p is not None:
        v &= (1 << p.bits) - 1
    return v


def gf_to_bytes(a: int, p: Params) -> bytes:
    return (int(a) & ((1 << p.bits) - 1)).to_bytes(p.fbytes, "little")


def gf_nonzero(a: int) -> int:
    return a if a != 0 else 1


def gf_poly_eval(coeffs: Sequence[int], x: int, p: Params) -> int:
    acc = 0
    for c in reversed(coeffs):
        acc = gf_mul(acc, x, p) ^ c
    return acc


# ---------------------------------------------------------------------------
# BLAKE3 / WH512 / KDF / transcript
# ---------------------------------------------------------------------------


def wh512(data: bytes) -> bytes:
    """Wide BLAKE3: two independent 256-bit derivations -> 512-bit output."""
    a = blake3.blake3(data, derive_key_context="VORB3-WH512-A-V1").digest(length=32)
    b = blake3.blake3(data, derive_key_context="VORB3-WH512-B-V1").digest(length=32)
    return a + b


def kdf32(context: str, data: bytes) -> bytes:
    return blake3.blake3(data, derive_key_context=context).digest(length=32)


def kdf64(context: str, data: bytes) -> bytes:
    return blake3.blake3(data, derive_key_context=context).digest(length=64)


def kdf_bytes(context: str, data: bytes, n: int) -> bytes:
    return blake3.blake3(data, derive_key_context=context).digest(length=n)


def _u64(n: int) -> bytes:
    if n < 0 or n > 0xFFFF_FFFF_FFFF_FFFF:
        raise ValueError("length out of range")
    return n.to_bytes(8, "little")


def _frame(label: bytes, data: bytes) -> bytes:
    return _u64(len(label)) + label + _u64(len(data)) + data


class Transcript:
    def __init__(self) -> None:
        self.state = wh512(b"VORB3-TRANSCRIPT-INIT-V1")

    def absorb(self, label: str, data: bytes) -> None:
        lb = label.encode("ascii")
        self.state = wh512(
            b"VORB3-TRANSCRIPT-ABSORB-V1" + self.state + _frame(lb, data)
        )

    def squeeze(self, label: str, n: int) -> bytes:
        lb = label.encode("ascii")
        out = wh512(
            b"VORB3-TRANSCRIPT-SQUEEZE-V1"
            + self.state
            + _frame(lb, _u64(n))
        )[:n]
        self.state = wh512(
            b"VORB3-TRANSCRIPT-RATCHET-V1" + self.state + _u64(n) + out
        )
        return out


# ---------------------------------------------------------------------------
# Rain-SP: field-linear diffusion + zero-safe inversion gadget
# ---------------------------------------------------------------------------


@dataclasses.dataclass
class RainConstants:
    c: List[int]
    k: List[int]


def rain_constants(p: Params) -> RainConstants:
    tag = f"VORB3-RAIN{p.bits}-SP"
    seed = f"{tag}-CONSTANTS-V1".encode()
    cs: List[int] = []
    ks: List[int] = []
    for r in range(p.rounds):
        cs.append(
            gf_nonzero(
                gf_from_bytes(kdf_bytes(f"{tag}-C{r}-V1", seed, p.fbytes), p)
            )
        )
        ks.append(
            gf_nonzero(
                gf_from_bytes(kdf_bytes(f"{tag}-K{r}-V1", seed, p.fbytes), p)
            )
        )
    return RainConstants(cs, ks)


@dataclasses.dataclass
class RainWitness:
    x: List[int]
    y: List[int]
    b: List[int]
    s: List[int]
    ct: int


def rain_encrypt(p: Params, sk: int, pt: int, consts: RainConstants) -> RainWitness:
    x_l: List[int] = []
    y_l: List[int] = []
    b_l: List[int] = []
    s_l: List[int] = []
    s = pt
    for r in range(p.rounds):
        x = s ^ sk ^ consts.k[r]
        b = 1 if x == 0 else 0
        y = gf_inv(x, p)
        z = gf_mul(consts.c[r], y, p)
        x_l.append(x)
        y_l.append(y)
        b_l.append(b)
        s_l.append(z)
        s = z
    return RainWitness(x_l, y_l, b_l, s_l, s ^ sk)


def rain_ct(p: Params, sk: int, pt: int, consts: RainConstants) -> int:
    return rain_encrypt(p, sk, pt, consts).ct


# ---------------------------------------------------------------------------
# GGM + Merkle commitment tree
# ---------------------------------------------------------------------------


@dataclasses.dataclass
class TreeData:
    levels: List[List[bytes]]
    u: List[int]
    com: List[bytes]
    hashes: List[List[bytes]]
    root: bytes
    copath: Optional[List[bytes]] = None
    hidden_u: Optional[int] = None
    hidden_com: Optional[bytes] = None


def _ggm_children(
    p: Params, parent: bytes, j: int, level: int, idx: int, salt: bytes, pk_hash: bytes
) -> Tuple[bytes, bytes]:
    data = (
        b"VORB3-GGM-EXPAND-V1"
        + salt
        + pk_hash
        + j.to_bytes(2, "little")
        + bytes([level])
        + idx.to_bytes(2, "little")
        + parent
    )
    out = blake3.blake3(data, derive_key_context="VORB3-GGM-EXPAND-V1").digest(
        length=2 * p.seed_len
    )
    return out[: p.seed_len], out[p.seed_len :]


def _leaf_u(seed: bytes, p: Params) -> int:
    return gf_nonzero(gf_from_bytes(seed, p))


def _leaf_com(
    p: Params, j: int, idx: int, u: int, salt: bytes, pk_hash: bytes
) -> bytes:
    data = (
        b"VORB3-GGM-LEAF-V1"
        + salt
        + pk_hash
        + j.to_bytes(2, "little")
        + idx.to_bytes(2, "little")
        + gf_to_bytes(u, p)
    )
    return wh512(data)


def _node_hash(
    p: Params,
    j: int,
    level: int,
    idx: int,
    left: bytes,
    right: bytes,
    salt: bytes,
    pk_hash: bytes,
) -> bytes:
    data = (
        b"VORB3-GGM-NODE-V1"
        + salt
        + pk_hash
        + j.to_bytes(2, "little")
        + bytes([level])
        + idx.to_bytes(2, "little")
        + left
        + right
    )
    return wh512(data)


def build_tree(
    p: Params, root_seed: bytes, j: int, salt: bytes, pk_hash: bytes
) -> TreeData:
    levels: List[List[bytes]] = [[root_seed]]
    for level in range(p.depth):
        nxt: List[bytes] = []
        for idx, parent in enumerate(levels[level]):
            l, r = _ggm_children(p, parent, j, level, idx, salt, pk_hash)
            nxt.extend((l, r))
        levels.append(nxt)
    us = [_leaf_u(seed, p) for seed in levels[p.depth]]
    coms = [_leaf_com(p, j, i, u, salt, pk_hash) for i, u in enumerate(us)]
    hash_levels: List[List[bytes]] = [[b""] * (1 << l) for l in range(p.depth + 1)]
    hash_levels[p.depth] = coms
    for level in range(p.depth - 1, -1, -1):
        cur = []
        for idx in range(1 << level):
            left = hash_levels[level + 1][2 * idx]
            right = hash_levels[level + 1][2 * idx + 1]
            cur.append(_node_hash(p, j, level, idx, left, right, salt, pk_hash))
        hash_levels[level] = cur
    return TreeData(levels, us, coms, hash_levels, hash_levels[0][0])


def tree_copath(t: TreeData, p: Params, alpha: int) -> List[bytes]:
    """Copath order: level depth (leaf sibling) first, then ... level 1."""
    path: List[bytes] = []
    for level in range(p.depth, 0, -1):
        node_idx = alpha >> (p.depth - level)
        sib = node_idx ^ 1
        path.append(t.levels[level][sib])
    return path


def _subtree_hash(
    p: Params,
    seed: bytes,
    j: int,
    level: int,
    idx: int,
    salt: bytes,
    pk_hash: bytes,
) -> bytes:
    if level == p.depth:
        u = _leaf_u(seed, p)
        return _leaf_com(p, j, idx, u, salt, pk_hash)
    left_seed, right_seed = _ggm_children(p, seed, j, level, idx, salt, pk_hash)
    left = _subtree_hash(p, left_seed, j, level + 1, 2 * idx, salt, pk_hash)
    right = _subtree_hash(p, right_seed, j, level + 1, 2 * idx + 1, salt, pk_hash)
    return _node_hash(p, j, level, idx, left, right, salt, pk_hash)


def reconstruct_root(
    p: Params,
    j: int,
    alpha: int,
    hidden_com: bytes,
    copath: Sequence[bytes],
    salt: bytes,
    pk_hash: bytes,
) -> bytes:
    if len(copath) != p.depth:
        raise ValueError("bad copath length")
    h = hidden_com
    for level in range(p.depth, 0, -1):
        sib_seed = copath[p.depth - level]
        sib_idx = (alpha >> (p.depth - level)) ^ 1
        sib = _subtree_hash(p, sib_seed, j, level, sib_idx, salt, pk_hash)
        parent_idx = alpha >> (p.depth - level + 1)
        if sib_idx & 1:
            left, right = h, sib
        else:
            left, right = sib, h
        h = _node_hash(p, j, level - 1, parent_idx, left, right, salt, pk_hash)
    return h


# ---------------------------------------------------------------------------
# Key generation / helpers
# ---------------------------------------------------------------------------


@dataclasses.dataclass
class KeyPair:
    seed: bytes
    sk: int
    pt: int
    ct: int
    pk: bytes


def keygen(p: Params, seed: bytes, consts: RainConstants) -> KeyPair:
    sk = gf_nonzero(gf_from_bytes(kdf_bytes("VORB3-KEYGEN-SK-V1", seed, p.fbytes), p))
    pt = gf_nonzero(gf_from_bytes(kdf_bytes("VORB3-KEYGEN-PT-V1", seed, p.fbytes), p))
    ct = rain_ct(p, sk, pt, consts)
    pk = gf_to_bytes(pt, p) + gf_to_bytes(ct, p)
    return KeyPair(seed, sk, pt, ct, pk)


def _chi_powers(chi: int, n: int, p: Params) -> List[int]:
    out = [1]
    for _ in range(1, n):
        out.append(gf_mul(out[-1], chi, p))
    return out


# ---------------------------------------------------------------------------
# Signature encode/decode
# ---------------------------------------------------------------------------


@dataclasses.dataclass
class Signature:
    salt: bytes
    h2: bytes
    wire_d: List[bytes]
    U: bytes
    V: bytes
    out_tag: bytes
    copaths: List[List[bytes]]
    hidden_coms: List[bytes]

    def encode(self, p: Params) -> bytes:
        parts = [self.salt, self.h2]
        parts.extend(self.wire_d)
        parts.extend([self.U, self.V, self.out_tag])
        for cp in self.copaths:
            parts.extend(cp)
        parts.extend(self.hidden_coms)
        out = b"".join(parts)
        if len(out) != p.sig_len():
            raise ValueError(f"signature length {len(out)} != {p.sig_len()}")
        return out

    @classmethod
    def decode(cls, p: Params, data: bytes) -> "Signature":
        if len(data) != p.sig_len():
            raise ValueError("bad signature length")
        off = 0
        salt = data[off : off + p.salt_len]; off += p.salt_len
        h2 = data[off : off + p.h2_len]; off += p.h2_len
        wd = []
        for _ in range(p.secret_wires):
            wd.append(data[off : off + p.fbytes]); off += p.fbytes
        U = data[off : off + p.fbytes]; off += p.fbytes
        V = data[off : off + p.fbytes]; off += p.fbytes
        out_tag = data[off : off + p.fbytes]; off += p.fbytes
        cps = []
        for _ in range(p.trees):
            cp = []
            for _ in range(p.depth):
                cp.append(data[off : off + p.seed_len]); off += p.seed_len
            cps.append(cp)
        coms = []
        for _ in range(p.trees):
            coms.append(data[off : off + p.com_len]); off += p.com_len
        if off != len(data):
            raise ValueError("trailing bytes")
        return cls(salt, h2, wd, U, V, out_tag, cps, coms)


# ---------------------------------------------------------------------------
# Sign
# ---------------------------------------------------------------------------


@dataclasses.dataclass
class SignTrace:
    sig: Signature
    delta: int
    chi: int
    roots: List[bytes]
    gates: int


def sign(p: Params, kp: KeyPair, msg: bytes, entropy: bytes, consts: RainConstants) -> SignTrace:
    if len(entropy) != 32:
        raise ValueError("entropy must be 32 bytes")
    if kp.sk == 0 or kp.pt == 0 or kp.ct == 0:
        raise ValueError("degenerate key")
    pk_hash = wh512(b"VORB3-PK-HASH-V1" + kp.pk)
    master = kdf_bytes(
        "VORB3-HEDGED-V1",
        gf_to_bytes(kp.sk, p) + kp.pk + _u64(len(msg)) + msg + entropy,
        p.fbytes,
    )
    salt = wh512(b"VORB3-SALT-V1" + master)

    trees: List[TreeData] = []
    roots: List[bytes] = []
    for j in range(p.trees):
        root_seed = kdf_bytes(
            "VORB3-TREE-ROOT-V1", master + j.to_bytes(2, "little"), p.seed_len
        )
        t = build_tree(p, root_seed, j, salt, pk_hash)
        trees.append(t)
        roots.append(t.root)

    tr = Transcript()
    tr.absorb("PK", kp.pk)
    tr.absorb("SALT", salt)
    tr.absorb("MSG", msg)
    tr.absorb("ROOTS", b"".join(roots))
    delta = gf_nonzero(gf_from_bytes(tr.squeeze("DELTA", p.fbytes), p))
    chi = gf_nonzero(gf_from_bytes(tr.squeeze("CHI", p.fbytes), p))
    h2 = tr.squeeze("H2", p.h2_len)

    mask = (1 << p.depth) - 1
    alphas = [h2[j] & mask for j in range(p.trees)]

    for j, t in enumerate(trees):
        t.copath = tree_copath(t, p, alphas[j])
        t.hidden_u = t.u[alphas[j]]
        t.hidden_com = t.com[alphas[j]]

    rw = rain_encrypt(p, kp.sk, kp.pt, consts)
    wire_w = [kp.sk] + list(rw.y) + list(rw.b)
    wire_u = [trees[i].hidden_u for i in range(p.secret_wires)]
    wire_q = [gf_from_bytes(trees[i].hidden_com[: p.fbytes], p) for i in range(p.secret_wires)]
    wire_d = [u ^ w for u, w in zip(wire_u, wire_w)]
    wire_v = [q ^ gf_mul(u, delta, p) for q, u in zip(wire_q, wire_u)]
    wire_q_open = [q ^ gf_mul(d, delta, p) for q, d in zip(wire_q, wire_d)]
    for q, d, v, w in zip(wire_q, wire_d, wire_v, wire_w):
        if q ^ gf_mul(d, delta, p) != v ^ gf_mul(w, delta, p):
            raise AssertionError("wire MAC mismatch")

    q_sk, v_sk = wire_q_open[0], wire_v[0]
    q_y = wire_q_open[1 : 1 + p.rounds]
    v_y = wire_v[1 : 1 + p.rounds]
    q_b = wire_q_open[1 + p.rounds : 1 + 2 * p.rounds]
    v_b = wire_v[1 + p.rounds : 1 + 2 * p.rounds]

    q_zero = 0
    v_zero = 0
    q_one = delta
    v_one = 0

    q_s = gf_mul(kp.pt, delta, p)
    v_s = 0
    a0s: List[int] = []
    a1s: List[int] = []
    bs: List[int] = []
    w_x_last = 0
    q_x_last = 0
    v_x_last = 0
    for r in range(p.rounds):
        w_x = rw.x[r]
        q_x = q_s ^ q_sk ^ gf_mul(consts.k[r], delta, p)
        v_x = v_s ^ v_sk
        if w_x != (rw.x[r]):
            raise AssertionError("x mismatch")
        w_y = rw.y[r]
        q_yi = q_y[r]
        v_yi = v_y[r]
        w_s = rw.s[r]
        q_si = gf_mul(consts.c[r], q_yi, p)
        v_si = gf_mul(consts.c[r], v_yi, p)
        if w_s != gf_mul(consts.c[r], w_y, p):
            raise AssertionError("s mismatch")
        w_b = rw.b[r]
        q_bi = q_b[r]
        v_bi = v_b[r]
        w_one_b = 1 ^ w_b
        q_one_b = delta ^ q_bi
        v_one_b = v_bi

        gates = [
            (w_b, v_bi, q_bi, w_b, v_bi, q_bi, w_b, v_bi, q_bi),
            (w_b, v_bi, q_bi, w_x, v_x, q_x, 0, 0, 0),
            (w_b, v_bi, q_bi, w_y, v_yi, q_yi, 0, 0, 0),
            (w_x, v_x, q_x, w_y, v_yi, q_yi, w_one_b, v_one_b, q_one_b),
        ]
        for wa, va, qa, wb, vb, qb, wc, vc, qc in gates:
            A0 = gf_mul(va, vb, p)
            A1 = gf_mul(wa, vb, p) ^ gf_mul(wb, va, p) ^ vc
            B = gf_mul(qa, qb, p) ^ gf_mul(qc, delta, p)
            if B != (A0 ^ gf_mul(A1, delta, p)):
                raise AssertionError("gate equation mismatch")
            a0s.append(A0)
            a1s.append(A1)
            bs.append(B)
        q_s = q_si
        v_s = v_si
        w_x_last = w_x
        q_x_last = q_x
        v_x_last = v_x

    if rw.ct != (rw.s[-1] ^ kp.sk):
        raise AssertionError("ciphertext mismatch")
    q_ct = q_s ^ q_sk
    v_ct = v_s ^ v_sk
    if q_ct != (gf_mul(kp.ct, delta, p) ^ v_ct):
        raise AssertionError("output tag mismatch")

    powers = _chi_powers(chi, len(a0s), p)
    A0 = 0
    A1 = 0
    B = 0
    for p_i, a0, a1, b in zip(powers, a0s, a1s, bs):
        A0 ^= gf_mul(a0, p_i, p)
        A1 ^= gf_mul(a1, p_i, p)
        B ^= gf_mul(b, p_i, p)
    if B != (A0 ^ gf_mul(A1, delta, p)):
        raise AssertionError("batch mismatch")

    u_star = trees[p.mask_tree].hidden_u
    q_star = gf_from_bytes(trees[p.mask_tree].hidden_com[: p.fbytes], p)
    v_star = q_star ^ gf_mul(u_star, delta, p)
    U = A0 ^ v_star
    V = A1 ^ u_star
    if (B ^ q_star) != (U ^ gf_mul(V, delta, p)):
        raise AssertionError("mask check mismatch")

    sig = Signature(
        salt=salt,
        h2=h2,
        wire_d=[gf_to_bytes(x, p) for x in wire_d],
        U=gf_to_bytes(U, p),
        V=gf_to_bytes(V, p),
        out_tag=gf_to_bytes(v_ct, p),
        copaths=[t.copath for t in trees],
        hidden_coms=[t.hidden_com for t in trees],
    )
    return SignTrace(sig, delta, chi, roots, len(a0s))


# ---------------------------------------------------------------------------
# Verify
# ---------------------------------------------------------------------------


@dataclasses.dataclass
class VerifyTrace:
    ok: bool
    reason: str
    gates: int
    roots: List[bytes]


def verify(
    p: Params,
    kp: KeyPair,
    msg: bytes,
    sig_bytes: bytes,
    consts: RainConstants,
) -> VerifyTrace:
    try:
        sig = Signature.decode(p, sig_bytes)
    except Exception as e:
        return VerifyTrace(False, f"decode:{e}", 0, [])
    if len(kp.pk) != 2 * p.fbytes or kp.pt == 0 or kp.ct == 0:
        return VerifyTrace(False, "invalid-pk", 0, [])

    mask = (1 << p.depth) - 1
    alphas = [sig.h2[j] & mask for j in range(p.trees)]
    pk_hash = wh512(b"VORB3-PK-HASH-V1" + kp.pk)
    roots: List[bytes] = []
    for j in range(p.trees):
        roots.append(
            reconstruct_root(
                p,
                j,
                alphas[j],
                sig.hidden_coms[j],
                sig.copaths[j],
                sig.salt,
                pk_hash,
            )
        )

    tr = Transcript()
    tr.absorb("PK", kp.pk)
    tr.absorb("SALT", sig.salt)
    tr.absorb("MSG", msg)
    tr.absorb("ROOTS", b"".join(roots))
    delta = gf_nonzero(gf_from_bytes(tr.squeeze("DELTA", p.fbytes), p))
    chi = gf_nonzero(gf_from_bytes(tr.squeeze("CHI", p.fbytes), p))
    h2p = tr.squeeze("H2", p.h2_len)
    if h2p != sig.h2:
        return VerifyTrace(False, "h2", 0, roots)

    q_wire = [gf_from_bytes(sig.hidden_coms[i][: p.fbytes], p) for i in range(p.secret_wires)]
    d_wire = [gf_from_bytes(x, p) for x in sig.wire_d]
    qp_wire = [q ^ gf_mul(d, delta, p) for q, d in zip(q_wire, d_wire)]
    q_sk = qp_wire[0]
    q_y = qp_wire[1 : 1 + p.rounds]
    q_b = qp_wire[1 + p.rounds : 1 + 2 * p.rounds]

    q_zero = 0
    q_s = gf_mul(kp.pt, delta, p)
    B = 0
    powers = _chi_powers(chi, 4 * p.rounds, p)
    idx = 0
    for r in range(p.rounds):
        q_x = q_s ^ q_sk ^ gf_mul(consts.k[r], delta, p)
        q_si = gf_mul(consts.c[r], q_y[r], p)
        q_bi = q_b[r]
        q_one_b = delta ^ q_bi
        gates = [
            (q_bi, q_bi, q_bi),
            (q_bi, q_x, q_zero),
            (q_bi, q_y[r], q_zero),
            (q_x, q_y[r], q_one_b),
        ]
        for qa, qb, qc in gates:
            B ^= gf_mul(
                gf_mul(qa, qb, p) ^ gf_mul(qc, delta, p),
                powers[idx],
                p,
            )
            idx += 1
        q_s = q_si

    q_ct = q_s ^ q_sk
    v_ct = gf_from_bytes(sig.out_tag, p)
    if q_ct != (v_ct ^ gf_mul(kp.ct, delta, p)):
        return VerifyTrace(False, "output-tag", idx, roots)

    q_star = gf_from_bytes(sig.hidden_coms[p.mask_tree][: p.fbytes], p)
    U = gf_from_bytes(sig.U, p)
    V = gf_from_bytes(sig.V, p)
    if (B ^ q_star) != (U ^ gf_mul(V, delta, p)):
        return VerifyTrace(False, "proof", idx, roots)
    return VerifyTrace(True, "ok", idx, roots)


# ---------------------------------------------------------------------------
# Self-tests
# ---------------------------------------------------------------------------


def _selftest(p: Params, msg: bytes = b"VORB3 phase-0 self-test") -> None:
    consts = rain_constants(p)
    _base = hashlib.sha256(b"VORB3 model seed" + str(p).encode()).digest()
    seed = (_base * ((p.fbytes + len(_base) - 1) // len(_base)))[: p.fbytes]
    kp = keygen(p, seed, consts)
    tr = sign(p, kp, msg, bytes(32), consts)
    data = tr.sig.encode(p)
    assert len(data) == p.sig_len(), (len(data), p.sig_len())
    vt = verify(p, kp, msg, data, consts)
    if not vt.ok:
        raise AssertionError(f"valid signature rejected: {vt.reason}")
    print(
        f"[+] {p.bits}-bit toy={p.bits==32} trees={p.trees} depth={p.depth} "
        f"rounds={p.rounds} gates={tr.gates} sig={len(data)} verify=ok"
    )

    # Wrong message
    if verify(p, kp, msg + b"x", data, consts).ok:
        raise AssertionError("wrong message accepted")
    # Wrong public key
    other = keygen(p, hashlib.sha256(seed + b"other").digest(), consts)
    if verify(p, other, msg, data, consts).ok:
        raise AssertionError("wrong key accepted")
    # Single-bit mutations at every top-level field
    wd_start = p.salt_len + p.h2_len
    u_start = wd_start + p.secret_wires * p.fbytes
    v_start = u_start + p.fbytes
    out_start = v_start + p.fbytes
    cp_start = out_start + p.fbytes
    hc_start = cp_start + p.trees * p.depth * p.seed_len
    positions = [0, p.salt_len, wd_start, u_start, v_start, out_start,
                 cp_start, hc_start, len(data) - 1]
    for pos in positions:
        mut = bytearray(data)
        mut[pos] ^= 0x01
        if verify(p, kp, msg, bytes(mut), consts).ok:
            raise AssertionError(f"mutation accepted at {pos}")
    # Cross-tree transplants
    mut = bytearray(data)
    a = wd_start
    b = wd_start + p.fbytes
    mut[a:a+p.fbytes], mut[b:b+p.fbytes] = mut[b:b+p.fbytes], mut[a:a+p.fbytes]
    if verify(p, kp, msg, bytes(mut), consts).ok:
        raise AssertionError("wire_d transplant accepted")
    mut = bytearray(data)
    mut[hc_start:hc_start+p.com_len], mut[hc_start+p.com_len:hc_start+2*p.com_len] = (\
        mut[hc_start+p.com_len:hc_start+2*p.com_len], mut[hc_start:hc_start+p.com_len])
    if verify(p, kp, msg, bytes(mut), consts).ok:
        raise AssertionError("hidden_com transplant accepted")
    mut = bytearray(data)
    mut[cp_start:cp_start+p.seed_len], mut[cp_start+p.seed_len:cp_start+2*p.seed_len] = (\
        mut[cp_start+p.seed_len:cp_start+2*p.seed_len], mut[cp_start:cp_start+p.seed_len])
    if verify(p, kp, msg, bytes(mut), consts).ok:
        raise AssertionError("copath transplant accepted")
    print(f"[+] mutations/transplants rejected; sig_len={p.sig_len()} bytes")


def main(argv: Optional[Sequence[str]] = None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--full", action="store_true", help="run the 256-bit full-size model")
    ap.add_argument("--sp160", action="store_true", help="run the 320-bit SP-160 candidate")
    ap.add_argument("--sp288", action="store_true", help="run the 288-bit SP-128+ candidate")
    ap.add_argument("--both", action="store_true", help="run toy and 256-bit full")
    ap.add_argument("--all", action="store_true", help="run toy, 256, 288/33, 288/35, 288/36, 320/36, 320/40")
    args = ap.parse_args(argv)
    if args.sp288 or args.all:
        _selftest(SP288_33)
        _selftest(SP288_35)
        _selftest(SP288)
    if args.sp160 or args.all:
        _selftest(SP320_36)
        _selftest(SP160)
    if args.full or args.both or args.all:
        _selftest(FULL)
    if (not args.full and not args.sp160) or args.both or args.all:
        _selftest(TOY)
    return 0


if __name__ == "__main__":
    sys.exit(main())
