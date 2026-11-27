#!/usr/bin/env bash
# Secondary coverage-guided engine: build a temporary AFL++ harness around the
# public parser API and fuzz the existing libFuzzer parse corpus.
#
# Prerequisite: cargo +nightly afl config --build --plugins
# This intentionally keeps the `afl` crate out of the workspace dependency
# graph: it is a tool-only harness built under /tmp/opencode.
set -euo pipefail
cd "$(dirname "$0")/.."

seconds="${1:-300}"
work=$(mktemp -d /tmp/opencode/vorb3-afl.XXXXXX)
cleanup() {
  pkill -f "$work/target/release/vorb3-afl" 2>/dev/null || true
  sleep 1
  rm -rf "$work" 2>/dev/null || true
}
trap cleanup EXIT

mkdir -p "$work/src" "$work/in"
if [ -d fuzz/corpus/parse ]; then
  cp fuzz/corpus/parse/* "$work/in/" 2>/dev/null || true
fi
if [ -z "$(ls -A "$work/in" 2>/dev/null)" ]; then
  printf 'A' >"$work/in/seed"
fi

cat >"$work/Cargo.toml" <<TOML
[package]
name = "vorb3-afl"
version = "0.1.0"
edition = "2024"
publish = false

[dependencies]
afl = "0.18"
vorb3 = { path = "$(pwd)/vorb3" }

[profile.release]
opt-level = 3
lto = true
codegen-units = 1
panic = "abort"
TOML
cat >"$work/src/main.rs" <<'RUST'
use afl::fuzz;
use vorb3::keys::PublicKey;
use vorb3::signature::Signature;

fn main() {
    fuzz!(|data: &[u8]| {
        if let Ok(signature) = Signature::from_bytes(data) {
            let bytes = signature.to_bytes();
            let _ = Signature::from_bytes(&bytes);
        }
        let mut pk = [0u8; 72];
        for (index, slot) in pk.iter_mut().enumerate() {
            *slot = data.get(index).copied().unwrap_or(0);
        }
        if let Ok(public) = PublicKey::from_bytes(pk) {
            let _ = public.to_bytes();
        }
    });
}
RUST

( cd "$work" && CARGO_TARGET_DIR="$work/target" cargo +nightly afl build --release )

set +e
( cd "$work" && AFL_SKIP_CPUFREQ=1 AFL_NO_UI=1 \
  AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1 \
  timeout "$seconds" cargo +nightly afl fuzz \
  -i "$work/in" -o "$work/out" -m none -t 1000 -- "$work/target/release/vorb3-afl" \
  >"$work/run.log" 2>&1 )
status=$?
set -e
# timeout(1) returns 124 when the requested campaign duration elapses.
if [ "$status" -ne 0 ] && [ "$status" -ne 124 ]; then
  tail -20 "$work/run.log" >&2
  exit "$status"
fi

grep -E 'execs_done|execs_per_sec|saved_crashes|paths_total|run_time' \
  "$work/out/default/fuzzer_stats"
printf 'AFL CAMPAIGN COMPLETE (%ss, temp harness removed)\n' "$seconds"
