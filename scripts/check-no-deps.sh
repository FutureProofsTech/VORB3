#!/usr/bin/env bash
# Prove the shipped crate has no third-party runtime dependencies.
set -euo pipefail
cd "$(dirname "$0")/.."

mapfile -t tree_lines < <(cargo tree -p vorb3 --edges normal --locked --offline)
if [[ "${#tree_lines[@]}" -ne 1 ]]; then
    printf 'unexpected dependency tree:\n' >&2
    printf '%s\n' "${tree_lines[@]}" >&2
    exit 1
fi
printf 'dependency tree: %s\n' "${tree_lines[0]}"

if cargo tree -p vorb3 --edges normal --locked --offline --prefix none | grep -vq '^vorb3 '; then
    printf 'unexpected dependency line found\n' >&2
    exit 1
fi
printf 'zero runtime dependencies: OK\n'
