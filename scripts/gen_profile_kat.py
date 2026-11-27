#!/usr/bin/env python3
"""Generate KAT and differential files for the NIST-tier profiles."""

from __future__ import annotations

import hashlib
import pathlib
import random
import struct
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "model"))

import vorb3_model as model  # noqa: E402

PROFILES = {
    "sp160_32": (model.SP160_32, b"VORB3 phase-0 SP160_32"),
    "sp224_32": (model.SP224_32, b"VORB3 phase-0 SP224_32"),
}
LENGTHS = [
    0, 1, 7, 31, 32, 33, 63, 64, 65, 127, 128, 129, 255, 256, 257,
    511, 512, 513, 1023, 1024, 1025, 2047, 3000, 4095, 4096, 4097, 8191, 8192,
]


def main() -> int:
    kat = ROOT / "kat"
    for name, (params, message) in PROFILES.items():
        consts = model.rain_constants(params)
        seed = hashlib.sha256(f"VORB3 KAT seed {name}".encode()).digest()[: params.fbytes]
        key = model.keygen(params, seed, consts)
        trace = model.sign(params, key, message, bytes(32), consts)
        signature = trace.sig.encode(params)
        assert model.verify(params, key, message, signature, consts).ok
        (kat / f"seed_{name}.bin").write_bytes(seed)
        (kat / f"pk_{name}.bin").write_bytes(key.pk)
        (kat / f"sign_{name}.bin").write_bytes(signature)
        print(f"{name}: seed={len(seed)} pk={len(key.pk)} sig={len(signature)}")

        records = []
        for index, length in enumerate(LENGTHS):
            dseed = (
                hashlib.sha256(f"vorb3-{name}-diff-seed-{index}".encode()).digest()
                + hashlib.sha256(f"vorb3-{name}-diff-seed2-{index}".encode()).digest()[:4]
            )[: params.fbytes]
            entropy = hashlib.sha256(f"vorb3-{name}-diff-entropy-{index}".encode()).digest()
            msg = bytes((index * 37 + j * 11) & 0xFF for j in range(length))
            dkey = model.keygen(params, dseed, consts)
            dtrace = model.sign(params, dkey, msg, entropy, consts)
            dsig = dtrace.sig.encode(params)
            assert model.verify(params, dkey, msg, dsig, consts).ok
            records.append((dseed, dkey.pk, entropy, msg, dsig))
        with (kat / f"sign_diff_{name}.bin").open("wb") as handle:
            handle.write(b"VORB3DIFF1")
            handle.write(struct.pack("<H", len(records)))
            for dseed, pk, entropy, msg, dsig in records:
                handle.write(dseed)
                handle.write(pk)
                handle.write(entropy)
                handle.write(struct.pack("<I", len(msg)))
                handle.write(msg)
                handle.write(dsig)
        print(f"{name}: wrote {len(records)} signature differential cases")

        rng = random.Random(0x564F524233000000 + params.bits + params.trees)
        record_len = 4 * params.fbytes
        with (kat / f"field_{name}_diff.bin").open("wb") as handle:
            for index in range(4096):
                if index == 0:
                    a = 0
                    b = 0
                else:
                    a = model.gf_from_bytes(rng.randbytes(params.fbytes), params)
                    b = model.gf_from_bytes(rng.randbytes(params.fbytes), params)
                handle.write(model.gf_to_bytes(a, params))
                handle.write(model.gf_to_bytes(b, params))
                handle.write(model.gf_to_bytes(model.gf_mul(a, b, params), params))
                handle.write(model.gf_to_bytes(model.gf_inv(a, params), params))
        print(f"{name}: wrote {4096} field records ({record_len} bytes each)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
