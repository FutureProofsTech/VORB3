#!/usr/bin/env python3
"""Generate the GF(2^288) differential KAT file.

This is a local verification tool. It uses the independent Python model and
writes `kat/field_sp288_diff.bin` with records:

    a[36] || b[36] || (a*b)[36] || (a^-1)[36]

All values are canonical little-endian. The Rust integration test compares the
implementation against these vectors.
"""

from __future__ import annotations

import pathlib
import random
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "model"))

import vorb3_model as model  # noqa: E402


def main() -> int:
    params = model.SP288
    rng = random.Random(0x564F5242335350323838)  # "VORB3SP288"
    out = ROOT / "kat" / "field_sp288_diff.bin"
    out.parent.mkdir(parents=True, exist_ok=True)
    records = 512
    with out.open("wb") as handle:
        for index in range(records):
            if index == 0:
                a = 0
                b = 0
            else:
                a = model.gf_from_bytes(rng.randbytes(params.fbytes), params)
                b = model.gf_from_bytes(rng.randbytes(params.fbytes), params)
            product = model.gf_mul(a, b, params)
            inverse = model.gf_inv(a, params)
            handle.write(model.gf_to_bytes(a, params))
            handle.write(model.gf_to_bytes(b, params))
            handle.write(model.gf_to_bytes(product, params))
            handle.write(model.gf_to_bytes(inverse, params))
    print(f"wrote {records} records to {out} ({out.stat().st_size} bytes)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
