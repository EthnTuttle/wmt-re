# 02 — Sub-image format (`ih_magic` images inside the bundle)

Status: **VERIFIED** by disassembly of `ParseUpgradeFirmwareImage`
(FUN_004a6350) and cross-checked against both sample bundles with
`wmall.py` (every entry's recorded size equals `0xb8 + ih_encsize`).

Sub-images are the units actually sent to a miner. In the combined bundle
they are laid out end-to-end (see 01); each one is a self-contained image
with a plaintext 0xb8-byte header followed by an **encrypted** payload.

All integers little-endian.

## Header layout (0xb8 bytes)

```
offset  size  field
+0x00   4     ih_magic     = 0x9A5BA57C
+0x04   4     ih_tag       = 0x8C790AFE or 0x22FA87BD  (both observed/accepted)
+0x08   4     ih_version   packed version; top 5 bits = pi_version
                            (observed 0x10000000 → "v2", 0x18000000 → "v3";
                            tool shifts >>27 — VERIFIED on all 8 samples)
+0x0C   4     ih_time      build timestamp (unix seconds)
+0x10   8     (name/type area — not individually validated)
+0x14   4     ih_chiptype  0x3C45B000 (== 1011200000 decimal) marks BTROM-bound
                            boards; 0 in plain entries. Cross-checks the bundle
                            entry's chiptype string.
+0x18   4     (observed 0)
+0x1C   4     ih_auxsize   inner length ≈ enc_size − ~437 (per-image,
                            not constant); semantics UNVERIFIED (looks like a
                            second, inner payload length; NOT added to totals)
+0x20   4     ih_encsize   encrypted payload size; file total = 0xb8 + ih_encsize
                            (VERIFIED exactly on all 8 sample entries)
+0x24   ..    hash/signature area (16 bytes, likely MD5 of payload — UNVERIFIED)
+0x38   4     ih_reserved  observed 1 in all sample entries ("single member")
+0x3C   ..    padding/zeros up to +0xB8
+0xB8   ..    encrypted firmware payload, ih_encsize bytes
```

## Encryption state on the wire (VERIFIED)

The tool sends the sub-image to the miner **exactly as stored in the
bundle** — i.e. the tool performs *no* payload decryption in the 8889
upload path:

- `FUN_004a7290` (ReadFirmwareToCombinedUpgradeBuffer) stores raw bundle
  pointers in the selection map.
- `FUN_004793c0` (SendFirmwareToMiner) streams those bytes unchanged
  (u32 LE size prefix + 1024-byte chunks; see 04/05).

Consequences for a clean-room client: **no sub-image crypto is needed** —
parse the bundle, pick the entry, stream its bytes. Payload decryption
happens miner-side.

## Tool-side decryption path (context only, not needed for upgrade)

`FUN_004a6fa0` decrypts a whole single image file buffer in place with
AES-256-ECB (standard Rijndael; inverse S-box at 0x725110, block decrypt
FUN_0040ea20 called per 0x10 block from FUN_0045f110). Callers:
`FUN_004a7820` (loose .bin loader) and `FUN_0049e250` (the
`*_NeedUpgradeAgain.bin` convert-image loader, see 05).
Key derivation: **UNVERIFIED** — a 32-byte key is materialized in a local
buffer before `aes_init(0x20)`; the exact hash/inputs were not pinned down
(it is *not* one of the three static 8889 keys). Only relevant for reading
convert images or standalone factory .bin files, not for the 8889 upload.
