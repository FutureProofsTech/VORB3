#!/usr/bin/env bash
# Local supply-chain scan. No external runtime dependencies are expected.
set -euo pipefail
cd "$(dirname "$0")/.."

cargo tree --workspace --edges normal --locked --offline
cargo audit --no-fetch
cargo deny check advisories licenses bans sources
printf 'SECURITY SCAN: PASS\n'
