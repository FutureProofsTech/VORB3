# VORB3 fuzz workspace

Isolated from the shipped crate. Uses the cached `libfuzzer-sys` tooling only.

```bash
cargo fuzz run verify -- -max_total_time=3600
```

The target fixes the KAT public key and message, fuzzes the 13,672-byte
signature, and treats any accepted non-KAT signature as a crash.
