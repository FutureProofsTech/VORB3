#!/usr/bin/env bash
# Build the release library twice in independent target directories and compare
# the rlib bytes.
set -euo pipefail
cd "$(dirname "$0")/.."

export SOURCE_DATE_EPOCH=1700000000
export CARGO_INCREMENTAL=0
feature_args=()
if [ -n "${VORB3_FEATURES:-}" ]; then
  feature_args=(--features "$VORB3_FEATURES")
fi
for run in a b; do
  rm -rf "/tmp/opencode/vorb3-repro-$run"
  CARGO_TARGET_DIR="/tmp/opencode/vorb3-repro-$run" \
    cargo build -p vorb3 --release --lib "${feature_args[@]}" --offline >/dev/null
done
a=$(find /tmp/opencode/vorb3-repro-a -name 'libvorb3-*.rlib' -print -quit)
b=$(find /tmp/opencode/vorb3-repro-b -name 'libvorb3-*.rlib' -print -quit)
[ -n "$a" ] && [ -n "$b" ]
sha_a=$(sha256sum "$a" | cut -d' ' -f1)
sha_b=$(sha256sum "$b" | cut -d' ' -f1)
printf 'build A: %s\nbuild B: %s\n' "$sha_a" "$sha_b"
[ "$sha_a" = "$sha_b" ] || {
  printf 'reproducibility failure: rlibs differ\n' >&2
  exit 1
}
printf 'REPRODUCIBLE: byte-identical rlib\n'
