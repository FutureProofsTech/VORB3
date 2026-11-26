#!/usr/bin/env bash
# Multi-target libFuzzer campaign. cargo-fuzz enables ASan by default.
set -euo pipefail
cd "$(dirname "$0")/.."

seconds="${1:-600}"
cd fuzz
cargo +nightly fuzz build >/tmp/opencode/fuzz_build.log 2>&1
mkdir -p artifacts/{verify,verify_any,sign,parse,field,rain}
bin=target/x86_64-unknown-linux-gnu/release
for target in verify verify_any sign parse field rain; do
  case "$target" in
    sign) max_len=4096 ;;
    verify_any) max_len=14400 ;;
    parse) max_len=14000 ;;
    verify) max_len=13672 ;;
    *) max_len=72 ;;
  esac
  "$bin/$target" -max_total_time="$seconds" -max_len="$max_len" \
    -artifact_prefix="$PWD/artifacts/$target/" -print_final_stats=1 \
    "corpus/$target" >"/tmp/opencode/fuzz_${target}.log" 2>&1 &
done
wait
printf 'FUZZ CAMPAIGN COMPLETE\n'
