#!/usr/bin/env python3
"""Generate the curated NIST-tier benchmark report from raw bench output."""

from __future__ import annotations

import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
RAW = {
    "base": ROOT / "target/benchmark-results.md",
    "nist1": ROOT / "target/benchmark-results-nist1.md",
    "nist3": ROOT / "target/benchmark-results-nist3.md",
}
OUT = ROOT / "docs/NIST-BENCHMARKS.md"

PROFILES = {
    "base": {
        "label": "SP-288/35",
        "trees": 35,
        "sig": 13_672,
        "seed": 36,
        "pk": 72,
    },
    "nist1": {
        "label": "NIST Level 1+ (SP-160/32)",
        "trees": 32,
        "sig": 7_976,
        "seed": 20,
        "pk": 40,
    },
    "nist3": {
        "label": "NIST Level 3+ (SP-224/32)",
        "trees": 32,
        "sig": 10_296,
        "seed": 28,
        "pk": 56,
    },
}


def parse_report(path: pathlib.Path) -> tuple[dict[str, dict[str, str]], dict[str, str]]:
    text = path.read_text()
    rows: dict[str, dict[str, str]] = {}
    for line in text.splitlines():
        if not line.startswith("|") or line.startswith("|---"):
            continue
        cells = [cell.strip() for cell in line.strip().strip("|").split("|")]
        if len(cells) != 11 or cells[0] == "Category":
            continue
        rows[cells[1]] = dict(
            category=cells[0],
            mean=cells[2],
            median=cells[3],
            p95=cells[4],
            min=cells[5],
            max=cells[6],
            stddev=cells[7],
            ops=cells[8],
            samples=cells[9],
            inner=cells[10],
        )
    meta: dict[str, str] = {}
    for line in text.splitlines():
        match = re.match(r"- (.+?): `([^`]*)`", line)
        if match:
            meta[match.group(1).strip()] = match.group(2)
    max_rss = re.search(r"Max RSS: (\d+) MiB", text)
    if max_rss:
        meta["max_rss_mib"] = max_rss.group(1)
    sizes = {}
    for label in ("vorb3-bench", "vorb3-attack"):
        match = re.search(
            r"size " + re.escape(label) + r":\n\s*text\s+data\s+bss\s+dec\s+hex\s+filename\n\s*"
            r"(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+\S+\s+\S+",
            text,
        )
        if match:
            sizes[label] = match.groups()
    meta["sizes"] = sizes  # type: ignore[assignment]
    return rows, meta


def number(value: str) -> float:
    return float(value.replace(",", ""))


def median(rows: dict[str, dict[str, str]], name: str) -> float:
    return number(rows[name]["median"])


def find(rows: dict[str, dict[str, str]], prefix: str) -> str:
    matches = [name for name in rows if name.startswith(prefix)]
    if len(matches) != 1:
        raise SystemExit(f"benchmark prefix {prefix!r} matched {matches!r}")
    return matches[0]


def fmt_lat(ns: float) -> str:
    if ns >= 1_000_000:
        return f"{ns / 1_000_000:.3f} ms"
    if ns >= 1_000:
        return f"{ns / 1_000:.2f} µs"
    if ns >= 100:
        return f"{ns:.0f} ns"
    if ns >= 10:
        return f"{ns:.1f} ns"
    return f"{ns:.2f} ns"


def fmt_rate(ns: float) -> str:
    rate = 1_000_000_000.0 / ns
    if rate >= 1_000:
        return f"{rate:,.0f}/s"
    return f"{rate:,.1f}/s"


def ratio(ns: float, baseline: float) -> str:
    return f"{ns / baseline:.2f}×"


def headline_table(data: dict[str, dict[str, dict[str, str]]]) -> str:
    base = data["base"]
    pairs = [
        ("Key generation", "keygen_full"),
        ("Sign, 32 B", "sign.32B"),
        ("Verify, 32 B", "verify.32B"),
        ("Sign + verify, 32 B", "sign_verify.32B"),
        ("Field multiplication", "mul"),
        ("Field squaring", "square"),
        ("Field inversion", "inverse"),
        ("Rain-SP1 encryption", "encrypt"),
        ("GGM roots (all trees)", "roots."),
        ("GGM root reconstruction", "reconstruct_roots."),
        ("QuickSilver prove", "prove.60gates"),
        ("QuickSilver verify", "check_proof.60gates"),
        ("Public-key parse", "public_key.profile"),
        ("Signature parse", "signature.profile"),
    ]
    lines = [
        "| Operation | SP-288/35 | Level 1+ | Level 3+ | L1+ / base | L3+ / base |",
        "|---|---:|---:|---:|---:|---:|",
    ]
    for label, prefix in pairs:
        values = {}
        for key in ("base", "nist1", "nist3"):
            name = find(data[key], prefix)
            values[key] = median(data[key], name)
        lines.append(
            f"| {label} | {fmt_lat(values['base'])} ({fmt_rate(values['base'])}) "
            f"| {fmt_lat(values['nist1'])} ({fmt_rate(values['nist1'])}) "
            f"| {fmt_lat(values['nist3'])} ({fmt_rate(values['nist3'])}) "
            f"| {ratio(values['nist1'], values['base'])} "
            f"| {ratio(values['nist3'], values['base'])} |"
        )
    return "\n".join(lines)


def phase_table(
    rows: dict[str, dict[str, str]],
    full_name: str,
    phases: list[tuple[str, str]],
) -> str:
    entries = []
    for label, prefix in phases:
        name = find(rows, prefix)
        entries.append((label, median(rows, name)))
    total = sum(value for _, value in entries)
    lines = [
        "| Phase | Median | Share of phase sum |",
        "|---|---:|---:|",
    ]
    for label, value in entries:
        share = value / total * 100
        share_text = "<0.01%" if share < 0.01 else f"{share:.2f}%"
        lines.append(f"| {label} | {fmt_lat(value)} | {share_text} |")
    lines.append(f"| **Measured phase sum** | **{fmt_lat(total)}** | **100%** |")
    full = median(rows, full_name)
    lines.append(f"| Full operation | {fmt_lat(full)} | {full / total * 100:.2f}% of phase sum |")
    return "\n".join(lines)


def scaling_table(data: dict[str, dict[str, dict[str, str]]]) -> str:
    sizes = ["0B", "32B", "1KiB", "64KiB", "1MiB", "16MiB"]
    lines = [
        "| Message | L1+ sign | L1+ verify | L3+ sign | L3+ verify |",
        "|---:|---:|---:|---:|---:|",
    ]
    for size in sizes:
        cells = []
        for key in ("nist1", "nist3"):
            cells.append(fmt_lat(median(data[key], f"sign.{size}")))
            cells.append(fmt_lat(median(data[key], f"verify.{size}")))
        lines.append(f"| {size} | " + " | ".join(cells) + " |")
    return "\n".join(lines)


def full_table_with_names(rows: dict[str, dict[str, str]]) -> str:
    lines = [
        "| Category | Benchmark | Mean ns/op | Median ns/op | p95 ns/op | Min ns/op | Max ns/op | Stddev ns | Ops/s | Samples | Inner |",
        "|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|",
    ]
    for name, row in rows.items():
        lines.append(
            f"| {row['category']} | {name} | {row['mean']} | {row['median']} | {row['p95']} "
            f"| {row['min']} | {row['max']} | {row['stddev']} | {row['ops']} "
            f"| {row['samples']} | {row['inner']} |"
        )
    return "\n".join(lines)


def main() -> int:
    data = {}
    metas = {}
    for key, path in RAW.items():
        if not path.exists():
            raise SystemExit(f"missing raw benchmark report: {path}")
        data[key], metas[key] = parse_report(path)
    meta = metas["nist1"]

    sign_phases = [
        ("GGM root derivation", "roots."),
        ("Rain-SP1 encryption", "encrypt"),
        ("QuickSilver prover", "prove.60gates"),
        ("Hidden openings", "openings."),
        ("Wire/tag construction", "wires."),
        ("Transcript", "challenges.32B"),
        ("Master seed", "master_seed.32B"),
        ("Salt", "salt"),
        ("Public-key hash", "pk_hash"),
    ]
    verify_phases = [
        ("GGM root reconstruction", "reconstruct_roots."),
        ("QuickSilver verifier", "check_proof.60gates"),
        ("Wire openings", "opened_wires."),
        ("Transcript", "challenges.32B"),
        ("Rain constants", "constants_derive"),
    ]

    n1_sign = phase_table(data["nist1"], "sign.32B", sign_phases)
    n3_sign = phase_table(data["nist3"], "sign.32B", sign_phases)
    n1_verify = phase_table(data["nist1"], "verify.32B", verify_phases)
    n3_verify = phase_table(data["nist3"], "verify.32B", verify_phases)

    def med(key: str, name: str) -> float:
        return median(data[key], name)

    def slope(key: str, op: str) -> float:
        return (med(key, f"{op}.16MiB") - med(key, f"{op}.0B")) / 16.0 / 1_000_000.0

    sign_b, sign_1, sign_3 = (med(key, "sign.32B") for key in ("base", "nist1", "nist3"))
    ver_b, ver_1, ver_3 = (med(key, "verify.32B") for key in ("base", "nist1", "nist3"))
    rain_b, rain_1, rain_3 = (med(key, "encrypt") for key in ("base", "nist1", "nist3"))
    inv_b, inv_1, inv_3 = (med(key, "inverse") for key in ("base", "nist1", "nist3"))
    sq_b, sq_1, sq_3 = (med(key, "square") for key in ("base", "nist1", "nist3"))
    roots_b, roots_1, roots_3 = (med(key, find(data[key], "roots.")) for key in ("base", "nist1", "nist3"))
    recon_b, recon_1, recon_3 = (
        med(key, find(data[key], "reconstruct_roots.")) for key in ("base", "nist1", "nist3")
    )
    pk_b, pk_1, pk_3 = (med(key, "public_key.profile") for key in ("base", "nist1", "nist3"))
    sig_b, sig_1, sig_3 = (med(key, "signature.profile") for key in ("base", "nist1", "nist3"))
    slope_sign_b, slope_ver_b = slope("base", "sign"), slope("base", "verify")
    slope_sign_1, slope_ver_1 = slope("nist1", "sign"), slope("nist1", "verify")
    slope_sign_3, slope_ver_3 = slope("nist3", "sign"), slope("nist3", "verify")

    doc = f"""# VORB3 NIST-Tier Full Benchmarks

**Status:** local measurement checkpoint (2026-11-27). Machine- and
compiler-dependent evidence, not a security proof and not an external audit.

This report covers the two compact packs plus the SP-288/35 baseline measured
on the same host in the same session. The raw tables are emitted by
`scripts/bench.sh`; this file is the curated snapshot. See
`docs/BENCHMARKS.md` for the earlier baseline analysis. The compact packs use
bit-interleaved squaring, word-level reduction, and an Itoh-Tsujii inversion
chain; the SP-288/35 baseline is unchanged.

- host: `{meta['host']}`
- cpu: `{meta['cpu']}`
- cores/threads: `{meta['cores/threads']}`
- rustc: `{meta['rustc']}`
- cargo: `{meta['cargo']}`
- profile: release, opt-level=3, LTO, codegen-units=1, panic=abort, strip
- benchmark CPU pin: `{meta['cpu pin']}`
- signatures: SP-288/35 13,672 B; Level 1+ 7,976 B; Level 3+ 10,296 B
- keys: SP-288/35 36/72 B; Level 1+ 20/40 B; Level 3+ 28/56 B

## 1. Headline results

Medians from 25 samples per benchmark. Throughput is `1 / median`.

{headline_table(data)}

### Observations

- Level 1+ signing is **{sign_1 / sign_b:.2f}×** the SP-288/35 baseline;
  Level 3+ is **{sign_3 / sign_b:.2f}×** (below 1.00× is faster).
- Verification is **{ver_1 / ver_b:.2f}×** (Level 1+) and
  **{ver_3 / ver_b:.2f}×** (Level 3+); the packs use 32 trees instead of 35.
- Rain-SP1 encryption is {fmt_lat(rain_1)} (Level 1+) and {fmt_lat(rain_3)}
  (Level 3+) versus {fmt_lat(rain_b)} baseline. Field inversion is
  {fmt_lat(inv_1)} / {fmt_lat(inv_3)} versus {fmt_lat(inv_b)}; the
  Itoh-Tsujii chain uses `n = BITS - 1` squarings and about `log2(n)`
  multiplications instead of `n - 1` multiplications.
- Compact-field squaring is now {fmt_lat(sq_1)} / {fmt_lat(sq_3)}, close to
  the 288-bit specialized squaring ({fmt_lat(sq_b)}).
- GGM roots are {roots_1 / roots_b:.2f}× / {roots_3 / roots_b:.2f}× and root
  reconstruction is {recon_1 / recon_b:.2f}× / {recon_3 / recon_b:.2f}× the
  baseline because the packs use 32 trees instead of 35.
- Public-key parsing is {pk_1 / pk_b:.2f}× / {pk_3 / pk_b:.2f}× and signature
  parsing is {sig_1 / sig_b:.2f}× / {sig_3 / sig_b:.2f}× baseline, in
  proportion to the smaller encodings.

## 2. Where signing time goes

Independent phase medians; the measured phase sum can differ from the
end-to-end operation by a few percent because each row is sampled separately.

### Level 1+

{n1_sign}

### Level 3+

{n3_sign}

## 3. Where verification time goes

### Level 1+

{n1_verify}

### Level 3+

{n3_verify}

## 4. Message-size scaling

{scaling_table(data)}

At 16 MiB, signing costs about **{slope_sign_1:.2f} ms/MiB** (Level 1+) and
**{slope_sign_3:.2f} ms/MiB** (Level 3+) over the empty-message case;
verification costs about **{slope_ver_1:.2f} ms/MiB** and
**{slope_ver_3:.2f} ms/MiB**. The baseline slopes are {slope_sign_b:.2f}
ms/MiB and {slope_ver_b:.2f} ms/MiB. Signing hashes the message twice;
verification hashes it once.

## 5. Build and memory

| Profile | bench text | bench data | bench bss | bench dec | attack text | attack data | attack bss | attack dec | Max RSS |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| SP-288/35 | {metas['base']['sizes']['vorb3-bench'][0]} | {metas['base']['sizes']['vorb3-bench'][1]} | {metas['base']['sizes']['vorb3-bench'][2]} | {metas['base']['sizes']['vorb3-bench'][3]} | {metas['base']['sizes']['vorb3-attack'][0]} | {metas['base']['sizes']['vorb3-attack'][1]} | {metas['base']['sizes']['vorb3-attack'][2]} | {metas['base']['sizes']['vorb3-attack'][3]} | {metas['base']['max_rss_mib']} MiB |
| Level 1+ | {metas['nist1']['sizes']['vorb3-bench'][0]} | {metas['nist1']['sizes']['vorb3-bench'][1]} | {metas['nist1']['sizes']['vorb3-bench'][2]} | {metas['nist1']['sizes']['vorb3-bench'][3]} | {metas['nist1']['sizes']['vorb3-attack'][0]} | {metas['nist1']['sizes']['vorb3-attack'][1]} | {metas['nist1']['sizes']['vorb3-attack'][2]} | {metas['nist1']['sizes']['vorb3-attack'][3]} | {metas['nist1']['max_rss_mib']} MiB |
| Level 3+ | {metas['nist3']['sizes']['vorb3-bench'][0]} | {metas['nist3']['sizes']['vorb3-bench'][1]} | {metas['nist3']['sizes']['vorb3-bench'][2]} | {metas['nist3']['sizes']['vorb3-bench'][3]} | {metas['nist3']['sizes']['vorb3-attack'][0]} | {metas['nist3']['sizes']['vorb3-attack'][1]} | {metas['nist3']['sizes']['vorb3-attack'][2]} | {metas['nist3']['sizes']['vorb3-attack'][3]} | {metas['nist3']['max_rss_mib']} MiB |

The library remains `no_std`, allocates no heap, and has zero runtime
dependencies. The profile `nist_stack` tests pass at 32 KiB for sign/verify
and 64 KiB when the 7,976/10,296-byte signature buffer itself is placed on the
stack.

The `public_key.profile` and `signature.profile` rows parse the profile's
40/56-byte public key and 7,976/10,296-byte signature respectively.

## 6. Full Level 1+ results

{full_table_with_names(data['nist1'])}

## 7. Full Level 3+ results

{full_table_with_names(data['nist3'])}

## 8. Reproduce

```bash
BENCH_CPU=4 ./scripts/bench.sh
VORB3_FEATURES=nist1 BENCH_CPU=4 BENCH_OUT=target/benchmark-results-nist1.md ./scripts/bench.sh
VORB3_FEATURES=nist3 BENCH_CPU=4 BENCH_OUT=target/benchmark-results-nist3.md ./scripts/bench.sh
python3 scripts/gen_nist_bench_report.py
```

The harness auto-calibrates each inner loop, records 25 samples, and reports
mean, median, p95, min, max, standard deviation, and operations/second.

## 9. Caveats

- One machine and one compiler version; this is not a controlled lab.
- The benchmark was pinned to CPU 4; other long-running host jobs were
  restricted to CPUs 8-11 for the duration. Absolute numbers remain sensitive
  to frequency scaling, sibling-thread activity, and memory bandwidth.
- Microbenchmarks measure this implementation, not asymptotic complexity.
- No external audit; no constant-time or security claim follows from
  throughput.
"""
    OUT.write_text(doc)
    print(f"wrote {OUT}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
