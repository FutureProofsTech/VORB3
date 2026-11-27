#!/usr/bin/env python3
"""Verify the frozen profile polynomials are irreducible over GF(2)."""

from __future__ import annotations

import sympy as sp


def main() -> int:
    x = sp.symbols("x")
    profiles = {
        "SP-288/35": x**288 + x**11 + x**10 + x + 1,
        "SP-160/32": x**160 + x**5 + x**3 + x**2 + 1,
        "SP-224/32": x**224 + x**9 + x**8 + x**3 + 1,
    }
    ok = True
    for name, expression in profiles.items():
        polynomial = sp.Poly(expression, x, modulus=2)
        irreducible = bool(polynomial.is_irreducible)
        print(f"{name}: degree={polynomial.degree()} irreducible={irreducible}")
        ok = ok and irreducible
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
