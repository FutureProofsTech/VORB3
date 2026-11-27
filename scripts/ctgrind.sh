#!/usr/bin/env bash
# Valgrind ctgrind: mark seed/entropy undefined, then detect any secret-dependent
# branch or memory address in key generation and signing.
set -euo pipefail
cd "$(dirname "$0")/.."

cargo build -p vorb3-ctgrind --release --offline \
  --config 'profile.release.debug=1' --config 'profile.release.strip=false'
cc -O2 -g tools/ctgrind/harness.c target/release/libvorb3_ctgrind.a \
  -o target/ctgrind -lpthread -ldl -lm -lrt -lutil

printf '== raw Valgrind (public-key validity declassification is expected) ==\n'
set +e
valgrind --error-exitcode=99 --track-origins=yes --leak-check=no --quiet \
  target/ctgrind >/tmp/opencode/ctgrind_raw.log 2>&1
raw_status=$?
set -e
cat /tmp/opencode/ctgrind_raw.log
if [ "$raw_status" -ne 99 ]; then
  printf 'unexpected raw Valgrind status: %s\n' "$raw_status" >&2
  exit 1
fi
raw_cond=$(grep -c 'Conditional jump or move depends on uninitialised value' /tmp/opencode/ctgrind_raw.log || true)
raw_from_bytes=$(grep -c 'from_bytes (keys.rs:25)' /tmp/opencode/ctgrind_raw.log || true)
printf 'raw conditional reports: %s total, %s at PublicKey::from_bytes\n' "$raw_cond" "$raw_from_bytes"
if [ "$raw_cond" -eq 0 ] || [ "$raw_cond" -ne "$raw_from_bytes" ]; then
  printf 'raw Valgrind found a report outside the documented public-key check\n' >&2
  exit 1
fi

printf '== suppressed public-key validity check ==\n'
valgrind --error-exitcode=99 --track-origins=yes --leak-check=no --quiet \
  --suppressions=tools/ctgrind/vorb3.supp \
  target/ctgrind >/tmp/opencode/ctgrind_suppressed.log 2>&1
cat /tmp/opencode/ctgrind_suppressed.log
printf 'CTGRIND PASS: no other secret-dependent branch or address\n'
