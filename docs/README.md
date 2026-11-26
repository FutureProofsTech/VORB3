# VORB3 Documentation Index (Phase 0)

**No production code yet.** Phase 0 is a specification/model freeze.

| Document | Purpose |
|---|---|
| `../PLAN.md` | Master plan; Revision 3 points to Phase 0 |
| `PHASE0-REPORT.md` | Findings, corrections, model results, decisions |
| `VORB3-SPEC-1.md` | Complete protocol/equation/wire specification |
| `WIRE-BINDING.md` | Byte-by-byte binding table |
| `THREAT-MODEL.md` | Assets, adversaries, trust boundaries |
| `ASSURANCE.md` | Requirement → evidence matrix |
| `SECURITY-CASE.md` | Security target, F-33 union bound, assumptions |
| `DECISIONS.md` | ADRs D1–D21 and findings F-01–F-33 |
| `PHASE0-REDTEAM.md` | Internal adversarial review |
| `PHASE1-4-REPORT.md` | Phase 1–4 implementation checkpoint |
| `../model/vorb3_model.py` | Independent Python/py-blake3 model |
| `../model/README.md` | Model usage and limitations |

## Current blocking decisions

- **D15** — field-linear Rain-SP1 (binary MDS rejected for compact field-VOLE).
- **D16** — 15 rounds, 31 wire openings + mask.
- **D17** — profile-sized signature layout.
- **D21 = SP-288/35 (selected):** 288-bit field, 35 trees, 13,672 B,
  ~140-bit quantum floor. SP-288/33 (12,968 B, ~132) is the smallest true-128+;
  SP-320/40 (16,848 B, ~156.5) is maximum margin; 256/32 (11,456 B) is ~125 and
  not a 128-bit claim.

Do not start the production crate until D15–D21 and the Phase-0 spec are signed
off.
