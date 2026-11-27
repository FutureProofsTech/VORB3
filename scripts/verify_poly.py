#!/usr/bin/env python3
"""Verify the frozen GF(2^288) polynomial is irreducible over GF(2)."""

from __future__ import annotations

import sympy as sp


def main() -> int:
    x = sp.symbols("x")
    polynomial = sp.Poly(x**288 + x**11 + x**10 + x + 1, x, modulus=2)
    print(f"degree: {polynomial.degree()}")
    print(f"irreducible: {polynomial.is_irreducible}")
    return 0 if polynomial.is_irreducible else 1


if __name__ == "__main__":
    raise SystemExit(main())
