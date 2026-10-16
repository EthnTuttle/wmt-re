# 03 — Sub-image selection (miner identity → bundle entry)

Status: format of the selection map **VERIFIED-tool** from
`ReadFirmwareToCombinedUpgradeBuffer` (FUN_004a7290) and
`DecideFirmWareDataBufferAndSize` (FUN_00462240); identity-field provenance
**VERIFIED-tool** from parser FUN_00470e50 string table; on-wire layout of
the identity reply **VERIFIED-live** on M64_VL40 fw 20250409.15.REL
(2026-10-15): one INI-ish `Key = Value` blob — the earlier "5 NUL-separated
ordered fields" prediction is **DISPROVEN** as the primary structure (see
below and 04 §9).

## Selection key

```
key = <chiptype> "-" <platform> [ "v2" | "v3" ] [ "-btrom" ]
```

- `chiptype`: miner-reported chip type; empty → literal `"0"`.
- `platform`: miner-reported platform, lowercased ("H616" → "h616").
- `vN`: tool-side the suffix actually comes from the **firmware file name**
  (FUN_0049c2f0: `.v3`/rel3 → "v3"; `.v2`/rel2/NeedUpgradeAgain → "v2";
  else "" → DECIDE's mode-0 branch rewrites ""/"v1" → "v2"), NOT from the
  identity blob — identity content has zero influence on selection
  (VERIFIED-tool, see appendix/selection-report.md). Clean-room rule that
  reproduces the tool's net behavior: default `v2` when the miner reports
  no PlatformVersion; `0-h616v3` is unreachable for `whatsminer-all-*`
  bundles (their names carry no v3 token).
- `-btrom`: appended when the miner reports `is_btrom` truthy, or when the
  candidate image's `ih_chiptype == 0x3C45B000` (== 1011200000) — the two
  sides must agree.

The complete key universe hardcoded in the tool (VERIFIED-tool, .rdata):

```
1011200000-h616-btrom      0-h616
1011200000-h616v2-btrom    0-h616v2
1011200000-h616v3-btrom    0-h616v3
```

(`-h616-btrom` without `vN` is the "V1" alias tried as a fallback —
error text: `TargetChipTypePlatform: %s, not found in CombinedUpgradePlatform V1`
vs the same without ` V1`.)

## Where the identity comes from (8889, see 04 §9)

Identity is queried per miner over 8889: cmdcode **0x16** (proto ≥ 8) or
**0x01** (legacy). The reply payload is **VERIFIED-live** (2026-10-15,
M64_VL40 fw 20250409.15.REL) to be one large INI-ish text blob:
`[MinerInfo]` / `[PowerInfo]` blocks of `Key = Value` lines, interleaved
with `#...#` separator records (MAC, `#web_pool=1,sshd=0#`, the
`#super=255 user1=0 ...#` permission bitmap), followed by cgminer-style
`SUMMARY` / `EDEVS` / `POOLS` / `#Uptime` CSV sections. Full layout:
04 §9; redacted capture:
[appendix/identity-2026-10-15-redacted.txt](appendix/identity-2026-10-15-redacted.txt).

The static-RE prediction "5 NUL-separated ordered fields, then
`#`-records" (the tool's handler FUN_00468960 walks 5 C-strings by strlen,
then counts `#`) is **DISPROVEN as the primary structure** on this
firmware — the blob does not cleanly delimit into 5 fields. **Parse the
`Key = Value` lines, not positional fields.** `Bound` ∈
{"bound","unbound","none"} and a fallback platform string "h6os" exist in
tool code (VERIFIED-tool) but were not needed on this firmware.

The tool's key parser is FUN_00470e50 (get-value-by-key helper
FUN_00476dd0). Complete key list (VERIFIED-tool, in table order; the live
reply carries the subset the miner reports — `MinerType`,
`ControlBoardType`, `ControlBoardVersion`, `HashBoardVersion`,
`PowerType`, `FirmwareVersion`, `ChipData`, `is_btrom`, `MinerSn`, … were
all observed):

```
MinerType ControlBoardType ControlBoardVersion HashBoardVersion
FirmwareVersion DetectedHashRate CoinType PoolStrategy LowPowerMode
PowerMode HeatMode HashPercent EepromLiquidCooling ChipDataAll
MinerApiSwitch BtminerFastMining BtminerFastBoot HashBoardStruct
PcbSn0..PcbSn7 PowerLimitSet UpfreqSpeed is_btrom joint_mining
MinerSn CustomerSn DisableFactoryMode DisableUpgrade RandomBootTime
```

Live resolution on the reference miner (M64_VL40, fw 20250409.15.REL,
2026-10-15): chiptype empty → `"0"`; platform from `ControlBoardType =
H616` → `h616`; `PlatformVersion` absent → `v2`; `is_btrom = 0` → no
`-btrom` suffix. Selection key = **`0-h616v2`**.

(Power-side reply variant, parser FUN_00475000: `PowerName PowerRevision
PowerOnOff MinerWasPoweroff PowerVender PowerModel PowerSerialNo
HwRevision`.) Upgrade-relevant: `FirmwareVersion`, `is_btrom`,
`DisableUpgrade`, `ControlBoardType/Version`, `HashBoardVersion` (parsed
for 'HB'/'_V' patterns), `ChipDataAll` (chip binning/date used by gates, 06).

## Which container kind is used (FUN_00466b30, VERIFIED-tool)

From the handshake protocol version:

| proto | package type |
|-------|--------------|
| < 6   | 0 — legacy single-file flow |
| 6..9  | 1 — combined bundle, legacy envelope |
| ≥ 10  | 2 — combined bundle, current flow |

`DecideFirmWareDataBufferAndSize` (FUN_00462e00) merges: selected map
entry **or** a convert-stage image (FUN_004631f0,
"miner version miss, load %s convert firmware" — see 05/06).

## Bundle entry table of the target file (for reference)

See 01 §"Observed entry table": the 20260908.12 bundle carries exactly the
four keys `0-h616v2`, `0-h616v3`, `1011200000-h616v2-btrom`,
`1011200000-h616v3-btrom`.

---
Live-confirmed against M64_VL40 fw 20250409.15.REL, 2026-10-15.
