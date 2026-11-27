#!/usr/bin/env bash
# Run the full test graph on two additional runtimes:
#   - powerpc64 (big-endian) musl under qemu-ppc64
#   - x86_64 Windows GNU under Wine
set -euo pipefail
cd "$(dirname "$0")/.."

MUSL_ROOT="${POWERPC64_MUSL_ROOT:-/tmp/opencode/powerpc64-linux-musl-cross}"
FEATURE_ARGS=()
if [ -n "${VORB3_FEATURES:-}" ]; then
  FEATURE_ARGS=(--features "$VORB3_FEATURES")
fi
MUSL_TARBALL="${POWERPC64_MUSL_TARBALL:-https://musl.cc/powerpc64-linux-musl-cross.tgz}"
WINEPREFIX="${WINEPREFIX:-/tmp/opencode/wineprefix}"
export WINEPREFIX WINEDEBUG="${WINEDEBUG:--all}"

if [ ! -x "$MUSL_ROOT/bin/powerpc64-linux-musl-gcc" ]; then
  tmp=$(mktemp -d /tmp/opencode/vorb3-musl.XXXXXX)
  trap 'rm -rf "$tmp"' EXIT
  curl -fsSL "$MUSL_TARBALL" -o "$tmp/musl.tgz"
  tar -xzf "$tmp/musl.tgz" -C "$(dirname "$MUSL_ROOT")"
fi

printf '== powerpc64 big-endian musl ==\n'
env \
  CARGO_TARGET_POWERPC64_UNKNOWN_LINUX_MUSL_LINKER="$MUSL_ROOT/bin/powerpc64-linux-musl-gcc" \
  CARGO_TARGET_POWERPC64_UNKNOWN_LINUX_MUSL_RUNNER=qemu-ppc64 \
  RUSTFLAGS='-C target-feature=+crt-static' VORB3_STACK_KB=128 \
  cargo test -p vorb3 --target powerpc64-unknown-linux-musl --release \
    "${FEATURE_ARGS[@]}" --offline
STACK_TEST=stack
if [ -n "${VORB3_FEATURES:-}" ]; then STACK_TEST=nist_stack; fi
if [ "$STACK_TEST" = nist_stack ]; then
  env \
    CARGO_TARGET_POWERPC64_UNKNOWN_LINUX_MUSL_LINKER="$MUSL_ROOT/bin/powerpc64-linux-musl-gcc" \
    CARGO_TARGET_POWERPC64_UNKNOWN_LINUX_MUSL_RUNNER=qemu-ppc64 \
    RUSTFLAGS='-C target-feature=+crt-static' VORB3_STACK_KB=32 \
    cargo test -p vorb3 --target powerpc64-unknown-linux-musl --release \
      "${FEATURE_ARGS[@]}" --test "$STACK_TEST" --offline -- --ignored
else
  env \
    CARGO_TARGET_POWERPC64_UNKNOWN_LINUX_MUSL_LINKER="$MUSL_ROOT/bin/powerpc64-linux-musl-gcc" \
    CARGO_TARGET_POWERPC64_UNKNOWN_LINUX_MUSL_RUNNER=qemu-ppc64 \
    RUSTFLAGS='-C target-feature=+crt-static' VORB3_STACK_KB=32 \
    cargo test -p vorb3 --target powerpc64-unknown-linux-musl --release \
      "${FEATURE_ARGS[@]}" --test "$STACK_TEST" --offline
fi

printf '== x86_64 Windows GNU under Wine ==\n'
command -v wine >/dev/null
command -v x86_64-w64-mingw32-gcc >/dev/null
env \
  CARGO_TARGET_X86_64_PC_WINDOWS_GNU_LINKER=x86_64-w64-mingw32-gcc \
  CARGO_TARGET_X86_64_PC_WINDOWS_GNU_RUNNER=wine VORB3_STACK_KB=128 \
  cargo test -p vorb3 --target x86_64-pc-windows-gnu --release \
    "${FEATURE_ARGS[@]}" --offline
if [ "$STACK_TEST" = nist_stack ]; then
  env \
    CARGO_TARGET_X86_64_PC_WINDOWS_GNU_LINKER=x86_64-w64-mingw32-gcc \
    CARGO_TARGET_X86_64_PC_WINDOWS_GNU_RUNNER=wine VORB3_STACK_KB=32 \
    cargo test -p vorb3 --target x86_64-pc-windows-gnu --release \
      "${FEATURE_ARGS[@]}" --test "$STACK_TEST" --offline -- --ignored
else
  env \
    CARGO_TARGET_X86_64_PC_WINDOWS_GNU_LINKER=x86_64-w64-mingw32-gcc \
    CARGO_TARGET_X86_64_PC_WINDOWS_GNU_RUNNER=wine VORB3_STACK_KB=32 \
    cargo test -p vorb3 --target x86_64-pc-windows-gnu --release \
      "${FEATURE_ARGS[@]}" --test "$STACK_TEST" --offline
fi

printf 'PORTABLE-RUNTIME PASS\n'
