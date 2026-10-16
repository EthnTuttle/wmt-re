# 01 — `Whatsminer-all-*.bin` combined bundle format

Status: **VERIFIED** against two independent bundles (20260908.12 and
20251209.16), cross-checked with `ReadFirmwareToCombinedUpgradeBuffer`
(FUN_004a7290) error strings and the CRC routine FUN_00492860.

All integers little-endian unless noted.

## Container layout

```
offset  size  field
0x0000  4     magic = 0xAE640A3F
0x0004  4     reserved (0)
0x0008  4     version timestamp (unix seconds; == epoch of the build,
              matches the filename suffix /1000: 0x6a9f8f2a ≈ 1789959400 ≈ 2026-09-08 build)
0x000c  4     reserved (0)
0x0010  4     total payload size = filesize − 0x1a9c  (sum of all sub-images, no padding)
0x0014  4     entry count N (observed: 4)
0x0018  N×0x68  entry table (see below)
0x01b8  ..    table slack up to header end (0x1a98)
0x1a98  4     CRC of header bytes [0, 0x1a98)  — see CRC section
0x1a9c  ..    concatenated sub-image payloads, in table order, no padding
```

## Entry table (0x68 bytes each, starting at 0x18)

```
+0x00  char[16]  chiptype   — ASCII, NUL-padded. Observed: "0", "1011200000"
+0x10  char[16]  platform   — ASCII, NUL-padded. Observed: "h616"
+0x20  u32       offset     — absolute file offset of the sub-image
+0x24  u32       size       — sub-image size in bytes
+0x28  u32       pi_version — 2 → "v2", 3 → "v3"
+0x2c  ..        remaining bytes of the 0x68 record: zeros (observed)
```

## Selection key (from ReadFirmwareToCombinedUpgradeBuffer string table)

The tool computes a lookup key for a miner and matches it against entries:

```
key = chiptype + "-" + platform + ["v2" if pi_version==2 | "v3" if 3] + ["-btrom" if btrom]
```

with format strings observed: `%s-%s-btrom`, `%s-%sv3-btrom` and plain variants.
`-btrom` is appended when chiptype == "1011200000" (== 0x3c45b000 as integer:
the SoC marks BTROM-bound boards this way). Errors:
`TargetChipTypePlatform: %s, not found in CombinedUpgradePlatform[ V1]`.

## CRC algorithm (VERIFIED, both sample files)

CRC-32 (zlib polynomial table, reflected), **init 0xFFFFFFFF, NO final XOR**,
over header bytes `[0, 0x1a98)`.

Reference: `zlib.crc32(hdr) ^ 0xFFFFFFFF` equals the stored word on both
bundles. Implementation in tool: FUN_00492860 (table `@0x732c18`,
`eax=0xffffffff` init, shifts-right loop, no final complement). The same
routine is reused as the 8889 packet checksum (see 04).

## Observed entry table — whatsminer-all-20260908.12

| # | chiptype    | platform | pi_version | offset     | size       | selection key               |
|---|-------------|----------|-----------|------------|------------|-----------------------------|
| 0 | 0           | h616     | 2         | 0x1a9c     | 13,025,864 | `0-h616v2`                  |
| 1 | 0           | h616     | 3         | 0xc6dce4   | 9,450,376  | `0-h616v3`                  |
| 2 | 1011200000  | h616     | 2         | 0x157106c  | 13,118,408 | `1011200000-h616v2-btrom`   |
| 3 | 1011200000  | h616     | 3         | 0x21f3c34  | 9,542,696  | `1011200000-h616v3-btrom`   |

20251209.16 has the identical 4-entry shape (sizes differ slightly).
Every sub-image begins with u32 magic 0x9A5BA57C ("ih_magic"; see 02).

## Sanity rules (from tool's validation strings)

- magic wrong → "Invalid firmware: magic error"
- header CRC wrong → "Invalid firmware: crc error"
- entry count bounded ("too many package number")
- per-entry offset/size must stay in file ("invalid package offset and size")
- pi_version ∈ {2,3} ("invalid package pi_version")
- package tag check ("invalid package ih_tag") — see 02.
