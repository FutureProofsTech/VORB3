#!/usr/bin/env bash
# Run the full vorb3 test graph on non-x86_64 Linux targets under qemu.
# Requires Fedora cross sysroots (sysroot-*-fc44-glibc) and qemu-user.
set -euo pipefail
cd "$(dirname "$0")/.."

AARCH64_SYSROOT=/usr/aarch64-redhat-linux/sys-root/fc44
S390X_SYSROOT=/usr/s390x-redhat-linux/sys-root/fc44
WORK=$(mktemp -d /tmp/opencode/vorb3-cross.XXXXXX)
trap 'rm -rf "$WORK"' EXIT

ensure_loader() {
  local sysroot=$1 loader=$2 pair name soname
  mkdir -p "$sysroot/lib" "$sysroot/lib64"
  for dir in lib lib64; do
    if [ ! -e "$sysroot/$dir/$loader" ] && [ ! -L "$sysroot/$dir/$loader" ]; then
      ln -s "../usr/lib/$loader" "$sysroot/$dir/$loader"
    fi
  done
  for pair in libutil.so:libutil.so.1 librt.so:librt.so.1 \
    libpthread.so:libpthread.so.0 libdl.so:libdl.so.2; do
    name=${pair%%:*}
    soname=${pair#*:}
    if [ ! -e "$sysroot/usr/lib64/$name" ] && [ ! -L "$sysroot/usr/lib64/$name" ]; then
      ln -s "$soname" "$sysroot/usr/lib64/$name"
    fi
  done
}

# Fedora's cross gcc omits libgcc_s and libatomic_asneeded from the sysroot.
make_wrapper() {
  local name=$1 compiler=$2 flags=$3 libs=$4
  cat > "$WORK/$name" <<WRAPPER
#!/bin/bash
args=()
for arg in "\$@"; do
  if [ "\$arg" = "-lgcc_s" ]; then continue; fi
  args+=("\$arg")
done
exec $compiler $flags "\${args[@]}" $libs
WRAPPER
  chmod +x "$WORK/$name"
}

make_wrapper aarch64-gcc /usr/bin/aarch64-linux-gnu-gcc \
  "--sysroot=$AARCH64_SYSROOT" /usr/lib/gcc/aarch64-linux-gnu/16/libgcc.a
make_wrapper s390x-gcc /usr/bin/s390x-linux-gnu-gcc \
  "-fno-link-libatomic --sysroot=$S390X_SYSROOT" /usr/lib/gcc/s390x-linux-gnu/16/libgcc.a
cat > "$WORK/i686-gcc" <<'WRAPPER'
#!/bin/sh
exec gcc -m32 "$@"
WRAPPER
chmod +x "$WORK/i686-gcc"

ensure_loader "$AARCH64_SYSROOT" ld-linux-aarch64.so.1
ensure_loader "$S390X_SYSROOT" ld64.so.1

run_full() {
  local target=$1 linker=$2 runner=$3 upper envs
  upper=$(printf '%s' "$target" | tr 'a-z-' 'A-Z_')
  envs=("CARGO_TARGET_${upper}_LINKER=$linker")
  if [ -n "$runner" ]; then
    envs+=("CARGO_TARGET_${upper}_RUNNER=$runner")
  fi
  printf '== %s full test graph ==\n' "$target"
  env "${envs[@]}" VORB3_STACK_KB=128 \
    cargo test -p vorb3 --target "$target" --release --all-features --offline
  printf '== %s 32 KiB stack target ==\n' "$target"
  env "${envs[@]}" VORB3_STACK_KB=32 \
    cargo test -p vorb3 --target "$target" --release --test stack --offline
}

run_full aarch64-unknown-linux-gnu "$WORK/aarch64-gcc" \
  "qemu-aarch64 -L $AARCH64_SYSROOT"
run_full s390x-unknown-linux-gnu "$WORK/s390x-gcc" \
  "qemu-s390x -L $S390X_SYSROOT -E LD_LIBRARY_PATH=$S390X_SYSROOT/usr/lib64:$S390X_SYSROOT/lib64"
run_full i686-unknown-linux-gnu "$WORK/i686-gcc" ""

printf 'CROSS-RUNTIME PASS\n'
