#!/usr/bin/env python3
"""Reduced-width theory probes for Rain-SP1.

These are sanity checks and bounds, not a proof of 128-bit security.
"""

from __future__ import annotations

import math
import pathlib
import random
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "model"))

import vorb3_model as model  # noqa: E402


def mul(a: int, b: int, bits: int, poly: int) -> int:
    result = 0
    while b:
        if b & 1:
            result ^= a
        b >>= 1
        a <<= 1
        if a >> bits:
            a ^= poly
    return result


def inv(a: int, bits: int, poly: int) -> int:
    if a == 0:
        return 0
    result = 1
    power = a
    exponent = (1 << bits) - 2
    while exponent:
        if exponent & 1:
            result = mul(result, power, bits, poly)
        power = mul(power, power, bits, poly)
        exponent >>= 1
    return result


def inversion_differential(bits: int, poly: int) -> tuple[int, float]:
    size = 1 << bits
    table = [inv(x, bits, poly) for x in range(size)]
    worst = 0
    for a in range(1, size):
        counts = [0] * size
        for x in range(size):
            counts[table[x] ^ table[x ^ a]] += 1
        worst = max(worst, max(counts))
    return worst, worst / size


def inversion_linearity(bits: int, poly: int) -> tuple[int, float]:
    """Max Walsh coefficient of the inversion permutation, via FWHT.

    For each output mask b, transform f_b(x) = (-1)^(b . x^-1). The maximum
    absolute Walsh coefficient over all nonzero input/output masks bounds the
    best single-round linear correlation.
    """
    size = 1 << bits
    table = [inv(x, bits, poly) for x in range(size)]
    parity = [bin(x).count("1") & 1 for x in range(size)]
    worst = 0
    for b in range(1, size):
        values = [(-1 if parity[b & table[x]] else 1) for x in range(size)]
        step = 1
        while step < size:
            for start in range(0, size, step * 2):
                for offset in range(start, start + step):
                    left = values[offset]
                    right = values[offset + step]
                    values[offset] = left + right
                    values[offset + step] = left - right
            step *= 2
        worst = max(worst, max(abs(value) for value in values))
    return worst, worst / size


def toy_encrypt(x: int, key: int, constants: list[int], diffusions: list[int], bits: int, poly: int) -> int:
    state = x
    for k, c in zip(constants, diffusions):
        y = inv(state ^ key ^ k, bits, poly)
        state = mul(c, y, bits, poly)
    return state ^ key


def toy_degree(bits: int, poly: int, rounds: int, seed: int = 7) -> list[int]:
    rng = random.Random(seed)
    key = rng.randrange(1, 1 << bits)
    constants = [rng.randrange(1, 1 << bits) for _ in range(rounds)]
    diffusions = [rng.randrange(1, 1 << bits) for _ in range(rounds)]
    size = 1 << bits
    degrees = [0] * bits
    for out_bit in range(bits):
        table = [((toy_encrypt(x, key, constants, diffusions, bits, poly) >> out_bit) & 1) for x in range(size)]
        # Möbius transform: ANF coefficients.
        coefficients = table[:]
        step = 1
        while step < size:
            for start in range(0, size, step * 2):
                for offset in range(start, start + step):
                    coefficients[offset + step] ^= coefficients[offset]
            step *= 2
        degree = max((bin(index).count("1") for index, value in enumerate(coefficients) if value), default=0)
        degrees[out_bit] = degree
    return degrees


def toy_differential(bits: int, poly: int, rounds: int, seed: int = 11) -> tuple[int, int, float]:
    rng = random.Random(seed)
    key = rng.randrange(1, 1 << bits)
    constants = [rng.randrange(1, 1 << bits) for _ in range(rounds)]
    diffusions = [rng.randrange(1, 1 << bits) for _ in range(rounds)]
    size = 1 << bits
    table = [toy_encrypt(x, key, constants, diffusions, bits, poly) for x in range(size)]
    worst = 0
    worst_distinct = 0
    for a in range(1, size):
        counts = [0] * size
        for x in range(size):
            counts[table[x] ^ table[x ^ a]] += 1
        worst = max(worst, max(counts))
        worst_distinct = min(worst_distinct or size, sum(1 for count in counts if count))
    return worst, worst_distinct, worst / size


def main() -> int:
    bits = 8
    poly = 0x11B  # x^8 + x^4 + x^3 + x + 1
    print("== inversion over GF(2^8) ==")
    worst, probability = inversion_differential(bits, poly)
    print(f"max differential count={worst}, DP={probability:.6f} (4/256={4/256:.6f})")
    for linear_bits, linear_poly in ((8, 0x11B), (10, 0x409)):
        walsh, correlation = inversion_linearity(linear_bits, linear_poly)
        print(
            f"GF(2^{linear_bits}) max Walsh={walsh}, correlation={correlation:.6f}"
        )

    print("== toy Rain algebraic degree (GF(2^8)) ==")
    for rounds in (1, 2, 3, 4, 15):
        degrees = toy_degree(bits, poly, rounds)
        print(f"rounds={rounds} max degree={max(degrees)} degrees={degrees[:8]}...")

    print("== toy Rain differential (GF(2^8)) ==")
    for rounds in (1, 2, 3, 4, 15):
        worst, distinct, probability = toy_differential(bits, poly, rounds)
        print(f"rounds={rounds} max count={worst} DP={probability:.6f} distinct_outputs={distinct}/256")

    print("== full-width differential composition bound ==")
    per_round_log2 = -288 + 2  # 4 / 2^288
    full_log2 = 2 * 15 - 288  # 4^r / 2^n
    print(f"per-round max DP <= 2^{per_round_log2}")
    print(f"15-round composition bound <= 2^{full_log2} (4^15 / 2^288)")
    print(f"numeric 2^{full_log2} = {2.0 ** full_log2:.3e}")
    print("NOTE: this composition bound is crude and weakens with r; it is not")
    print("a multi-round security proof.")

    print("== SP-288/35 constants ==")
    consts = model.rain_constants(model.SP288_35)
    all_values = list(consts.k) + list(consts.c)
    print(f"round constants={len(consts.k)} diffusion constants={len(consts.c)}")
    print(f"all nonzero={all(value != 0 for value in all_values)} distinct={len(set(all_values)) == len(all_values)}")
    weights = [value.bit_count() for value in all_values]
    print(f"constant Hamming weight min={min(weights)} max={max(weights)} mean={sum(weights)/len(weights):.1f}")
    print("NOTE: reduced-width probes do not prove the 288-bit instance.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
