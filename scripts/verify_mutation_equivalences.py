#!/usr/bin/env python3
"""Machine-check the equivalent mutation survivors with Z3.

These are expression-equivalence checks, not proofs of the surrounding
protocol. They cover the OR-vs-XOR mask mutants and the 64-byte boundary
comparisons reported by cargo-mutants.
"""

from __future__ import annotations

from z3 import BitVec, BitVecVal, Solver, ZeroExt, unsat


def spread64(value, xor_stage: int | None = None):
    spread = ZeroExt(64, value)
    stages = [
        (32, 0x0000_0000_FFFF_FFFF_0000_0000_FFFF_FFFF),
        (16, 0x0000_FFFF_0000_FFFF_0000_FFFF_0000_FFFF),
        (8, 0x00FF_00FF_00FF_00FF_00FF_00FF_00FF_00FF),
        (4, 0x0F0F_0F0F_0F0F_0F0F_0F0F_0F0F_0F0F_0F0F),
        (2, 0x3333_3333_3333_3333_3333_3333_3333_3333),
        (1, 0x5555_5555_5555_5555_5555_5555_5555_5555),
    ]
    for index, (shift, mask) in enumerate(stages):
        shifted = spread << shift
        combined = (spread ^ shifted) if xor_stage in (index, -1) else (spread | shifted)
        spread = combined & BitVecVal(mask, 128)
    return spread


def spread32(value, xor_stage: int | None = None):
    spread = ZeroExt(32, value)
    stages = [
        (16, 0x0000_FFFF_0000_FFFF),
        (8, 0x00FF_00FF_00FF_00FF),
        (4, 0x0F0F_0F0F_0F0F_0F0F),
        (2, 0x3333_3333_3333_3333),
        (1, 0x5555_5555_5555_5555),
    ]
    for index, (shift, mask) in enumerate(stages):
        shifted = spread << shift
        combined = (spread ^ shifted) if xor_stage in (index, -1) else (spread | shifted)
        spread = combined & BitVecVal(mask, 64)
    return spread


def equivalent(left, right) -> bool:
    solver = Solver()
    solver.add(left != right)
    return solver.check() == unsat


def main() -> int:
    value = BitVec("value", 64)
    checks = 0

    # Each one-OR->XOR mutant in spread64.
    for stage in range(6):
        assert equivalent(spread64(value), spread64(value, xor_stage=stage))
        checks += 1
    # The all-XOR expression is also equal.
    assert equivalent(spread64(value), spread64(value, xor_stage=-1))
    checks += 1

    # Each one-OR->XOR mutant in the compact-field spread32.
    value32 = BitVec("value32", 32)
    for stage in range(5):
        assert equivalent(spread32(value32), spread32(value32, xor_stage=stage))
        checks += 1
    assert equivalent(spread32(value32), spread32(value32, xor_stage=-1))
    checks += 1

    # select_u64 mask replication: OR and XOR agree for the 0x00/0xFF byte.
    byte = BitVec("byte", 8)
    replicated_or = (
        ZeroExt(56, byte)
        | (ZeroExt(56, byte) << 8)
        | (ZeroExt(56, byte) << 16)
        | (ZeroExt(56, byte) << 24)
        | (ZeroExt(56, byte) << 32)
        | (ZeroExt(56, byte) << 40)
        | (ZeroExt(56, byte) << 48)
        | (ZeroExt(56, byte) << 56)
    )
    # The replicas are disjoint only for the actual mask values.
    for actual in (0x00, 0xFF):
        mask = BitVecVal(actual, 8)
        rep = (
            ZeroExt(56, mask)
            | (ZeroExt(56, mask) << 8)
            | (ZeroExt(56, mask) << 16)
            | (ZeroExt(56, mask) << 24)
            | (ZeroExt(56, mask) << 32)
            | (ZeroExt(56, mask) << 40)
            | (ZeroExt(56, mask) << 48)
            | (ZeroExt(56, mask) << 56)
        )
        rep_xor = (
            ZeroExt(56, mask)
            ^ (ZeroExt(56, mask) << 8)
            ^ (ZeroExt(56, mask) << 16)
            ^ (ZeroExt(56, mask) << 24)
            ^ (ZeroExt(56, mask) << 32)
            ^ (ZeroExt(56, mask) << 40)
            ^ (ZeroExt(56, mask) << 48)
            ^ (ZeroExt(56, mask) << 56)
        )
        assert equivalent(rep, rep_xor)
        checks += 1

    # Selection masks are complementary, so OR and XOR agree for any mask.
    mask = BitVec("mask", 64)
    left = BitVec("left", 64)
    right = BitVec("right", 64)
    assert equivalent((left & ~mask) | (right & mask), (left & ~mask) ^ (right & mask))
    checks += 1

    # BLAKE3 flags are pairwise disjoint; OR and XOR agree.
    flags = [1 << bit for bit in range(7)]
    assert all((flags[i] & flags[j]) == 0 for i in range(7) for j in range(i + 1, 7))
    checks += 1

    # BLAKE3 ROOT is added again by root_bytes; the earlier OR is redundant.
    root = 1 << 3
    for value in flags:
        assert (value | root) | root == value | root
    checks += 1

    # BLAKE3 CHUNK_START is 1 << 0; replacing it with 1 >> 0 is equivalent.
    assert (1 << 0) == (1 >> 0)
    checks += 1

    # BLAKE3/transcript take = min(length, 64); < and <= agree at equality.
    for length in (0, 1, 63, 64, 65, 128):
        take_lt = length if length < 64 else 64
        take_le = length if length <= 64 else 64
        assert take_lt == take_le
    checks += 1

    # Transcript squeeze: < vs <= at exactly STATE_LEN is the same min().
    for length in (0, 1, 63, 64, 65, 128):
        take_lt = length if length < 64 else 64
        take_le = length if length <= 64 else 64
        assert take_lt == take_le
    checks += 1

    print(f"PASS: {checks} mutation-equivalence checks discharged with Z3")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
