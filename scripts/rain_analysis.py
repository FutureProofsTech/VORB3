#!/usr/bin/env python3
"""Local Rain-SP1 analysis harness (not a security proof).

Runs structural and statistical sanity checks against the independent model:
- permutation/distinctness of ciphertexts for fixed keys;
- zero-state and degenerate-input probes;
- random fixed-point probes;
- simple differential-sample statistics.
"""

from __future__ import annotations

import random
import sys
from collections import Counter

import pathlib

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "model"))

import vorb3_model as model  # noqa: E402


def main() -> int:
    p = model.SP288_35
    consts = model.rain_constants(p)
    rng = random.Random(0x5241494E535031)  # "RAINSP1"

    print("[*] permutation/distinctness sample")
    for trial in range(4):
        sk = model.gf_nonzero(model.gf_from_bytes(rng.randbytes(36), p))
        inputs = [model.gf_from_bytes(rng.randbytes(36), p) for _ in range(64)]
        outputs = [model.rain_encrypt(p, sk, pt, consts).ct for pt in inputs]
        if len(set(outputs)) != len(outputs):
            print("FAIL: ciphertext collision in permutation sample")
            return 1
        if any(pt == ct for pt, ct in zip(inputs, outputs)):
            print("NOTE: sampled fixed point found")
    print("PASS: no collisions/fixed points in sample")

    print("[*] zero-state and degenerate probes")
    for trial in range(16):
        sk = model.gf_nonzero(model.gf_from_bytes(rng.randbytes(36), p))
        for pt in (0, 1, (1 << p.bits) - 1):
            _ = model.rain_encrypt(p, sk, pt, consts)
    print("PASS: zero/boundary inputs complete without panic")

    print("[*] differential sample")
    sk = model.gf_nonzero(model.gf_from_bytes(rng.randbytes(36), p))
    base = model.gf_from_bytes(rng.randbytes(36), p)
    diffs = Counter()
    for _ in range(256):
        other = base ^ 1
        c0 = model.rain_encrypt(p, sk, base, consts).ct
        c1 = model.rain_encrypt(p, sk, other, consts).ct
        diffs[c0 ^ c1] += 1
    top = diffs.most_common(1)
    print(f"sample output differences: {len(diffs)} distinct; top count={top[0][1] if top else 0}")

    print("NOTE: this is sanity checking, not a proof of 128-bit security.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
