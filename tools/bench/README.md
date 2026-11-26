# vorb3-bench

Std-only benchmark harness for VORB3 SP-288/35. It has no third-party
dependencies and enables the non-default `vorb3/bench-api` feature to time
private GGM, transcript, and sign phases.

```bash
cargo build --release -p vorb3-bench
./target/release/vorb3-bench --quick
./target/release/vorb3-bench
./target/release/vorb3-bench --filter full
./target/release/vorb3-bench --csv > results.csv
```

The harness warms up, auto-calibrates an inner loop to a target sample time,
and reports mean/median/p95/min/max/stddev and ops/s. Run it on an idle machine;
absolute numbers depend on CPU frequency, sibling threads, and compiler version.
`scripts/bench.sh` wraps the build and report generation.
