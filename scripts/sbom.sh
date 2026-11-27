#!/usr/bin/env bash
# Regenerate the local CycloneDX SBOM snapshot for the shipped crate.
set -euo pipefail
cd "$(dirname "$0")/.."
mkdir -p docs/sbom
cargo cyclonedx --manifest-path "$(pwd)/vorb3/Cargo.toml" \
  -f json --describe crate -q
mv vorb3/vorb3.cdx.json docs/sbom/vorb3.cdx.json
rm -f tools/attack/vorb3-attack.cdx.json tools/bench/vorb3-bench.cdx.json \
  tools/ctgrind/vorb3-ctgrind.cdx.json
printf 'wrote docs/sbom/vorb3.cdx.json\n'
