#!/usr/bin/env python3
"""Z3 proof of the zero-safe selector gadget over toy GF(2^8).

This is a reduced-width formal cross-check, not a full 288-bit proof.
"""

from __future__ import annotations

from z3 import BitVec, BitVecVal, Extract, Not, Or, Solver, ZeroExt, sat, unsat


def gf_mul(a, b):
    aa = ZeroExt(8, a)
    res = BitVecVal(0, 16)
    for index in range(8):
        bit = Extract(index, index, b)
        term = aa << index
        res = res ^ (term & (BitVecVal(0xFFFF, 16) * ZeroExt(15, bit)))
    for index in range(15, 7, -1):
        bit = Extract(index, index, res)
        term = BitVecVal(0x11B, 16) << (index - 8)
        res = res ^ (term & (BitVecVal(0xFFFF, 16) * ZeroExt(15, bit)))
    return Extract(7, 0, res)


def main() -> int:
    x, y, b = BitVec("x", 8), BitVec("y", 8), BitVec("b", 8)
    solver = Solver()
    solver.add(gf_mul(b, b) == b)
    solver.add(gf_mul(b, x) == 0)
    solver.add(gf_mul(b, y) == 0)
    solver.add(gf_mul(x, y) == (1 ^ b))
    conclusion = Or(
        (b == 1) & (x == 0) & (y == 0),
        (b == 0) & (x != 0) & (gf_mul(x, y) == 1),
    )
    solver.add(Not(conclusion))
    result = solver.check()
    print(f"selector counterexample search: {result}")
    if result == unsat:
        print("PASS: every GF(2^8) solution is the zero case or the inverse case")
        return 0
    if result == sat:
        print(f"FAIL: counterexample {solver.model()}")
        return 1
    print("UNKNOWN: solver could not decide")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
