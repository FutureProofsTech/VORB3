# VORB3 Phase-0 Reference Model

`vorb3_model.py` is an independent executable specification for VORB3-SP1.
It is **not production code** and is not shipped.

## Independence

- Python big integers implement GF(2^bits) directly.
- `py-blake3` provides BLAKE3; it shares no code with the future Rust crate.
- No crate, no FFI, no Python crypto package beyond `blake3`.
- The model implements the equations; it does not import the Rust design.

## Run

```bash
python3 model/vorb3_model.py            # toy profile
python3 model/vorb3_model.py --full     # 256-bit equation baseline
python3 model/vorb3_model.py --sp288    # 288-bit SP-128+ candidate
python3 model/vorb3_model.py --sp160    # 320-bit SP-160 candidate
python3 model/vorb3_model.py --all      # all profiles
```

Each run:

- derives a keypair from a deterministic seed,
- signs a message with 32 zero entropy bytes,
- verifies the signature,
- rejects a wrong message, wrong key, and sampled bit mutations,
- checks every wire/gate/mask/output equation with assertions.

## Profiles

| Name | Field | Trees | Depth | Rounds | Signature | Minimum quantum floor |
|---|---|---:|---:|---:|---:|---:|
| TOY | 2^32 | 4 | 3 | 1 | 456 B | n/a |
| FULL | 2^256 | 32 | 8 | 15 | 11,456 B | ≈125 |
| SP288_33 | 2^288 | 33 | 8 | 15 | 12,968 B | ≈132 |
| SP288_35 | 2^288 | 35 | 8 | 15 | 13,672 B | ≈140 |
| SP288 | 2^288 | 36 | 8 | 15 | 14,024 B | ≈140 |
| SP320_36 | 2^320 | 36 | 8 | 15 | 15,312 B | ≈144 |
| SP160 | 2^320 | 40 | 8 | 15 | 16,848 B | ≈156 |

The floor is the minimum of the field-check, tree-challenge, key, and WH512
bounds; see `docs/SECURITY-CASE.md`. The 256-bit FULL profile is the equation
baseline, not a 128-bit claim.

## What the model proves

- Completeness of the selector gadget and QuickSilver equations.
- The wire MAC relations, gate equations, batching, mask, and output tag.
- GGM/Merkle root reconstruction from the copath.
- The signature length and field boundaries.
- Deterministic regression digests.

## What it does not prove

- Computational security of Rain-SP1.
- VOLEitH/QuickSilver soundness or ZK as theorems.
- Side-channel, zeroization, stack, or performance.
- BLAKE3/WH512 security.

Those are Phase 4–11 obligations.

## Determinism

`py-blake3` and the model are deterministic. The Phase-0 digests in
`docs/PHASE0-REPORT.md` are reproducible with the same inputs and profile.
The final KAT profile is selected by D21.
