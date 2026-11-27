#!/usr/bin/env python3
"""Generate multi-case Rust/Python signature differential KATs."""

from __future__ import annotations

import hashlib
import pathlib
import struct
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "model"))

import vorb3_model as model  # noqa: E402

MAGIC = b"VORB3DIFF1"
LENGTHS = [
    0, 1, 7, 31, 32, 33, 63, 64, 65, 127, 128, 129, 255, 256, 257,
    511, 512, 513, 1023, 1024, 1025, 2047, 3000, 4095, 4096, 4097, 8191, 8192,
]
CASES = len(LENGTHS)


def main() -> int:
    params = model.SP288_35
    constants = model.rain_constants(params)
    out = ROOT / "kat" / "sign_diff_sp288_35.bin"
    records = []
    for index in range(CASES):
        seed = (
            hashlib.sha256(f"vorb3-diff-seed-{index}".encode()).digest()
            + hashlib.sha256(f"vorb3-diff-seed2-{index}".encode()).digest()[:4]
        )
        entropy = hashlib.sha256(f"vorb3-diff-entropy-{index}".encode()).digest()
        length = LENGTHS[index]
        message = bytes((index * 37 + j * 11) & 0xFF for j in range(length))
        key = model.keygen(params, seed, constants)
        trace = model.sign(params, key, message, entropy, constants)
        signature = trace.sig.encode(params)
        assert model.verify(params, key, message, signature, constants).ok
        records.append((seed, key.pk, entropy, message, signature))
        print(f"case {index}: message={length} bytes, signature={len(signature)}")
    with out.open("wb") as handle:
        handle.write(MAGIC)
        handle.write(struct.pack("<H", CASES))
        for seed, pk, entropy, message, signature in records:
            handle.write(seed)
            handle.write(pk)
            handle.write(entropy)
            handle.write(struct.pack("<I", len(message)))
            handle.write(message)
            handle.write(signature)
    print(f"wrote {out} ({out.stat().st_size} bytes)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
