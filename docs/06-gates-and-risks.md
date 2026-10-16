# 06 — Gates, refusal conditions, and risks

Everything the tool checks *before or during* an upgrade, plus the
operational risks that matter for reproducing it. Confidence labels as
usual. "ctx+0xNNNN" = per-miner dialog state (GUI-bound).

## Tool-side refusals / gates (VERIFIED locations)

| gate | where | condition → effect |
|---|---|---|
| already upgrading / busy | FUN_00498110 | ctx+0x329c / ctx+0x29b4 → skip miner |
| liquid-cooled target | FUN_00498110 | flag set → **"The liquid cooled firmware cannot be upgraded, please use AirToLiquid"** |
| power-firmware target | FUN_00498110 | ctx+0x2a90==1 → **"Power firmware upgrade is not supported. Use AirToLiquid"** |
| proto < 4 | FUN_0047d790 → FUN_0047d070 | falls back to legacy MT99/MT03 flow (04 §12) |
| proto < 6 | FUN_00463830 | modern prepare/stream not available |
| proto < 7 | FUN_00467810 | no status polling (verdict unknown) |
| proto < 8 | FUN_00466cd0 | legacy identity cmd 0x01 |
| 6 ≤ proto < 15 (+ctx+0x3520==1) | FUN_00463830 | extra intermediate send FUN_00478890 first |
| proto < 14 | FUN_00476620 | only K1 used (K2 gated on ≥14) |
| `DisableUpgrade` | identity keys (FUN_00470e50) | miner reports upgrade disabled → tool respects it (DEDUCED semantics) |
| chip/firmware too old | FUN_004631f0 area | message **"The chip type is too old, please upgrade the firmware before 2026.0407"** → convert-stage path required first (05) |
| firmware newer than tool target | dialog flow | prompt **"Miner firmware is newer. Do Version Rollback?"** (DEDUCED: user-confirmed only) |

## Vendor constraint (user-provided, external)

MicroBT states **no rollback is possible once on 20260908.12**
(secure-boot chain / H616Sec). Treat the upgrade as one-way.

## Wire-level safety notes (VERIFIED-live unless marked)

- Replies carry result codes; **5 = Incorrect Password**,
  **9 = Need change pwd**. Modern 8889 auth **is** attached on every
  command: the text field is the envelope
  `<miner-ip>|<unixtime>|<user>|<pass>[|<flags>]` (04 §5,
  VERIFIED-live — supersedes the earlier "modern path sends no auth"
  note). A re-credentialed miner fails uploads with 5/9; a malformed
  envelope fails everything with 2. Factory defaults are `account==password`
  (`super`/`super`, …) per MicroBT's operation guide, and the identity
  reply's `#super=255 user1=0 …#` bitmap shows which accounts have 8889
  rights at all.
- Hello is cheap and read-only; identity (0x16) is read-only;
  **cmd 0x07 + bulk stream is the first state-changing step** (stages the
  image; flash happens miner-side after verify).
- Nothing in the flow reboots the miner from the tool — the miner
  reboots itself as part of applying the staged image (the `upgrade=`
  terminal state implies it; DEDUCED).
- Convert stage (05) flashes a *tool-local* intermediate image matched by
  chip/fw date; skipping it when required likely bricks or rejects —
  check the "before 2026.0407" predicate against the miner's
  `ChipDataAll`/FirmwareVersion before a straight jump.
  **UNVERIFIED**: exact date math (ini key `FwConvertDate`).

## Risks specific to the planned M64_VL40 run

1. **Liquid-cooled refusal**: M64 is hydro-cooled. The refusal in
   FUN_00498110 is GUI-state driven; whether a plain bundle upgrade of a
   hydro miner hits it is **UNVERIFIED** (flag origin unknown — possibly
   from `EepromLiquidCooling` in the identity reply). If the real tool
   upgrades this miner fine (it did offer the flow), a clean-room client
   that simply follows 05 won't reproduce that GUI-only check anyway.
2. **Wrong sub-image selection** is the biggest technical risk:
   `PlatformVersion` (v2 vs v3) and `is_btrom` come from the identity
   reply (03). Resolved live for the reference miner on 2026-10-15:
   `PlatformVersion` absent → v2, `is_btrom = 0` → key **`0-h616v2`**.
   Wrong pick → miner-side reject (result 4) most likely; worst case
   unbootable. Mitigate: capture identity first, parse by `Key = Value`
   (04 §9), match against the table, log the decision.
3. **Heat downtime**: miner is the primary heat source — check weather
   before the maintenance window (upgrade + reboot ≈ minutes–tens of
   minutes; poll loop until `upgrade=success`).
4. Tokens/passwords only via env/.env; never log them.

---
Live-confirmed against M64_VL40 fw 20250409.15.REL, 2026-10-15.
