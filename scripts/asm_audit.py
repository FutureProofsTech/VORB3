#!/usr/bin/env python3
"""Summarize release assembly for the secret-carrying VORB3 functions.

This is a review aid, not a formal constant-time verifier. It reports branch
and conditional-move counts per function; a human must confirm that every
conditional branch is on a public value (loop counter, public length, error).
"""

from __future__ import annotations

import pathlib
import re
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
TARGETS = (
    "hidden_opening",
    "tree_root",
    "sign_into",
    "verify_bytes",
    "fill_openings",
    "fill_wires",
    "prove",
    "check_proof",
    "opened_wires",
    "reconstruct_root",
    "subtree_hash",
    "rain.*encrypt",
    "mul_reduce",
    "select_bytes",
)


def newest_asm() -> pathlib.Path:
    candidates = sorted(
        (ROOT / "target" / "release" / "deps").glob("vorb3-*.s"),
        key=lambda path: path.stat().st_mtime,
        reverse=True,
    )
    if not candidates:
        subprocess.run(
            ["cargo", "rustc", "-p", "vorb3", "--release", "--lib", "--offline", "--", "--emit", "asm"],
            cwd=ROOT,
            check=True,
        )
        candidates = sorted(
            (ROOT / "target" / "release" / "deps").glob("vorb3-*.s"),
            key=lambda path: path.stat().st_mtime,
            reverse=True,
        )
    if not candidates:
        raise SystemExit("no emitted assembly found")
    return candidates[0]


def functions(lines: list[str]) -> dict[str, list[str]]:
    found: dict[str, list[str]] = {}
    current: str | None = None
    for line in lines:
        label = re.match(r"^([A-Za-z_][A-Za-z0-9_.$]*):\s*$", line)
        if label:
            current = label.group(1)
            if not current.startswith(".L"):
                found[current] = []
        elif current is not None:
            found[current].append(line)
    return found


def main() -> int:
    path = pathlib.Path(sys.argv[1]) if len(sys.argv) > 1 else newest_asm()
    print(f"assembly: {path}")
    print(f"lines: {len(path.read_text(errors='replace').splitlines())}")
    found = functions(path.read_text(errors="replace").splitlines())
    for name, body in sorted(found.items()):
        if not any(target in name for target in TARGETS):
            continue
        jumps = [line.strip() for line in body if re.match(r"^\s+j[a-z]+", line)]
        conditional = [line for line in body if re.match(r"^\s+j(?!mp)[a-z]+", line)]
        cmov = [line for line in body if "cmov" in line]
        calls = [line for line in body if re.match(r"^\s+callq?", line)]
        print(
            f"\n{name}\n  lines={len(body)} jumps={len(jumps)} "
            f"conditional={len(conditional)} cmov={len(cmov)} calls={len(calls)}"
        )
        for line in conditional[:20]:
            print(f"    {line}")
    print("\nManual gate: no conditional branch may depend on a secret value.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
