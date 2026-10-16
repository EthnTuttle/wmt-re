# 04 — WhatsMiner TCP/8889 "NetPacket" protocol

Clean-room spec of the binary protocol WhatsMinerTool 9.2.5 speaks on TCP
port **8889** (miner daemon `/usr/bin/api`).

Status: session model, framing, CRC coverage, key selection, the auth
envelope, hello semantics, result codes and the identity reply layout are
**VERIFIED-live** against M64_VL40 fw 20250409.15.REL (proto 16) on
2026-10-15. Command senders, bulk-upload/stream mechanics, legacy framing
and the version-gate table are **VERIFIED-tool** from static analysis of
`wmt925.exe` (MD5 62609e0755e1eb46471c7a6446989f18); function addresses
cited inline. Live-session evidence: [appendix/hello-audit-report.md](appendix/hello-audit-report.md),
[appendix/result16-report.md](appendix/result16-report.md),
[appendix/identity-2026-10-15-redacted.txt](appendix/identity-2026-10-15-redacted.txt)
(originals also in `/tmp/opencode/`). Working reference
implementation: `client/proto.py`.

## 1. Session model (VERIFIED-live)

- **One command per TCP connection.** Every operation = fresh connect to
  port 8889 → send exactly one packet → read exactly one reply → close.
  A second packet on the same socket gets EOF (observed live).
- The tool (and `client/proto.py`) therefore run hello on its own
  connection, then each real command on a *fresh* connection. Poll loops
  reconnect per iteration.
- Hello is retried up to 10× by the tool (FUN_00463560 → FUN_00464e70);
  each retry is a fresh connect.
- Defaults (CNetworkInterface ctor FUN_0040dd50): recv buffer 0x2010,
  30 s timeout, send socket buffer forced to 0x1000 during firmware bulk
  upload. Reply reader (FUN_00477e30/FUN_00477d10) stops when it holds
  ≥ 0x10 + u16@0xA bytes.
- Reply validator FUN_00469210: checks magic, checks the echoed cmdcode
  matches the request, checks CRC per §3.

## 2. Packet layout (VERIFIED-live; builder FUN_00476620)

Both directions use the same 16-byte little-endian header `<I I H H I`:

```
offset  size  requests                     replies
0x00    4     magic = 0x7F7F5A5A           magic echoed
0x04    4     cmdcode                      cmdcode echoed
0x08    2     text length                  result code (§7)
0x0A    2     attachment length            payload length
0x0C    4     CRC32 of payload (§3)        CRC32 of payload (§3)
0x10    ..    payload = text + attachment  payload
```

- Request payload = text (ASCII) immediately followed by attachment bytes;
  the two length fields split them.
- Requests: whole header+payload zero-padded to a multiple of 16, then
  AES-256-ECB encrypted (§4). On-wire size = `align16(16 + len1 + len2)`.
- **Replies are plaintext** — no AES on the receive path (VERIFIED-tool;
  confirmed live: replies parse as-is). Reply size = 16 + payload length,
  no padding.

## 3. Checksum (VERIFIED-live)

CRC-32, zlib polynomial table, **init 0xFFFFFFFF, no final XOR** — i.e.
`zlib.crc32(payload) ^ 0xFFFFFFFF` — over the **payload only**
(text + attachment, bytes `[0x10, 0x10+len1+len2)`). The header is NOT
covered. Routine: FUN_00492860 (same as bundle header CRC, see 01).

Reply-side validation follows the tool: verify the CRC **only when the
high 16 bits of the stored word are 0**, and then compare the low 16 bits.
Daemon error frames carry `crc = 0x0000ffff` as a skip marker.

## 4. Request encryption (VERIFIED-live)

- The **entire aligned request packet** (header + payload + zero pad) is
  AES-256-ECB encrypted before `send()` (FUN_0040e6c0/FUN_0040def0).
  Implementation is standard Rijndael/AES-256; pure Python suffices
  (FIPS-197 KAT green in `client/aes256.py`).
- Static 32-byte keys (`.data`, installed per-miner by FUN_00469510 —
  facts about wmt925.exe 9.2.5):

```
K1 @0x7254c0  f0d379ee4188bc6216cfa09adcd49100ee7f971217aaba26bc86c0b6ae1da90f
K2 @0x7254e0  66476cc48201182b9c27c302e48e120724a0e460fb970474a7539a48e787c296
K3 @0x725500  9be70afc109f7756383155083c120910ddfff76720a34786fa272611ead19bf1
```

- Key selection (sender FUN_00476620, confirmed live): **cmd 0 (hello)
  always uses K1**; all other commands use **K2 when proto ≥ 14, else K1**.
- K3 is installed but has no observed consumer — **UNVERIFIED**, likely
  legacy/fallback.
- Replies are never encrypted (§2).

## 5. Auth envelope on every command (VERIFIED-live — the #1 gotcha)

Every command's `text` field (including hello's) is an auth envelope built
by FUN_004641b0:

```
text = IP | "|" | unixtime | "|" | user | "|" | pass [ | "|" | hexflags ]
```

- **IP = the TARGET MINER'S OWN dotted-quad IP string** (e.g.
  `"10.0.0.104"`). The tool reuses the connect-target string here
  (dispatcher FUN_004abd10 copies the miner record's IP into the envelope;
  builder FUN_00476620 passes the same string to `inet_addr`). Sending an
  empty or wrong text yields **result 2 on every command regardless of
  credentials** (observed live; root cause of two audit rounds).
- `unixtime` = decimal epoch seconds; checked loosely (miner is
  NTP-synced).
- `user`/`pass`: factory default for every account is the account name
  itself (`super`/`super`, `admin`/`admin`, `user1`/`user1`, …).
  MicroBT's operation guide: *"The default password is the same as an
  account number."* (`vendor/wmtguide.txt` §6.)
- `hexflags` = lowercase `%x` of the session flags, appended **iff
  proto ≥ 14**. Flags come from the hello reply (§8). Hello itself is
  sent without the flags field.
- A further `|extra` field exists in the tool (ctx+0x355c) but is empty by
  default; omit it.
- Effective rights are per-account: the identity reply carries the 8889
  permission bitmap (`#super=255 user1=0 user2=0 user3=0#`; 255 = full,
  0 = none — §9). A sub-account with 0 rights fails even with the correct
  default password (observed live: `user1:user1` rejected).

## 6. Command codes (VERIFIED-tool at call sites; 0x00/0x16 also VERIFIED-live)

| cmdcode | op | sender | payload |
|---|---|---|---|
| 0x00 | hello | FUN_00464e70 | envelope text only; reply → §8 |
| 0x01 | identity (legacy, proto < 8) | FUN_00466cd0 | envelope text; reply → §9 |
| 0x16 | identity (proto ≥ 8) | FUN_00466cd0 | envelope text; reply → §9 |
| 0x07 | firmware prepare | FUN_00478b30 | envelope text; bulk stream follows — §10 |
| 0x0D | "set" | FUN_0047a2a0 | envelope text; **attachment `"3=1"`** (len2=3, built via `sprintf("%d=1", 3)`) — used as upgrade pre-flag when a dialog option (ctx+0x3514) is set |
| 0x14 | file/data download from miner | FUN_00463830 | proto ≥ 7 only; reply via bulk reader FUN_00477700 (e.g. log tgz) |
| 0x15 | upgrade-status poll | FUN_00467810 | envelope text; reply text `upgrade=…` — §11 |

Reply dispatcher (FUN_00469210): cmd 0 → FUN_004681d0 (hello parser);
1 → FUN_00468730; 0x13/0x16 → FUN_00468960 (identity parser); everything
else → generic result-code handler FUN_00467a70. cmdcode 0x13 is handled
but its sender was not located — **UNVERIFIED** (superseded identity
variant). Legacy text commands in the same string region (`MT25`, `MT16`,
`MT09`, `MT26`, pool formats, `/usr/bin/restore-factory-settings`) belong
to the port-4028 API / legacy framing (§12), not to modern 8889 packets.

## 7. Reply result codes (VERIFIED-tool: FUN_00467a70; 0/2 observed live)

Exhaustive — the switch on u16@0x08 has exactly these cases:

| code | tool's string | meaning |
|---|---|---|
| 0 | "Success" | success |
| 2 | NetPacket Error | generic reject: wrong envelope text (§5), bad creds, disallowed content — no further info |
| 3 | Invalid Command | cmdcode not supported |
| 4 | Data Error | payload/content rejected |
| 5 | Incorrect Password | auth failed |
| 6 | No Permission | account lacks the right (see §5 bitmap) |
| 7 | Miner Sys Error | daemon-side failure |
| 9 | Need change pwd | password must be changed (via official tool) before use |

All other codes are **unmapped**: FUN_00467a70 returns success-silently for
them. Note cmd-0 replies never reach this mapper at all — see §8 (the
hello "result" field is the protocol version, not an error code).

## 8. Hello (cmd 0) (VERIFIED-live)

Request: envelope text (§5), no attachment, always K1-encrypted.

The reply is special — **the u16 @0x08 carries the PROTOCOL VERSION, not a
result code** (parser FUN_004681d0):

```
proto = u16@0x08            if u16@0x08 >= 7        (modern daemons)
      = u32 @ payload+0     if u16@0x08 < 7 and payload non-empty   (legacy)
      = 0                   otherwise               (failure)
```

- **proto ≥ 1 means hello succeeded.** Do not route the field through the
  §7 table: "result 16" is not an error, it is a proto-16 advertisement
  (observed live on fw 20250409.15.REL; the tool accepts it on the first
  attempt and proceeds — retrier FUN_00463560 returns success whenever
  proto ≥ 1).
- When **proto ≥ 14**: session flags = **big-endian** u32 @ payload+4 (the
  tool does `ntohl`); banner cstring @ payload+8 (often empty). Feed the
  flags into the envelope `|hexflags` field of every later command and
  switch to K2.
- Observed live reply: u16@8 = 16, 8-byte payload = `<u32 legacy slot>
  <u32 BE flags>`, empty banner.

### Worked example (SYNTHETIC — computed from this spec, fixed timestamp)

Request, miner at 192.0.2.1, factory creds, unixtime 1760000000:

```
envelope text (32 B):  "192.0.2.1|1760000000|super|super"
plaintext frame (48 B = 16 hdr + 32 text, no pad needed):
  5a5a7f7f 00000000 2000 0000 775d68b4
  3139322e302e322e317c313736303030303030307c73757065727c7375706572
  (magic    cmd=0     len1=32 len2=0 crc=payload-crc; then ASCII envelope)
on-wire (AES-256-ECB K1, 48 B):
  f682a9daa8bf78e2b1641e9112361678bfd43470f725b41b8ab6947db6bb6ed6
  09dd9d46f14177b9438e03f2f0056e9e
```

Synthetic reply advertising proto 16, flags 0x00000001, empty banner
(24 B, plaintext):

```
5a5a7f7f 00000000 1000 0800 0010daed 00000000 00000001
(magic    cmd=0     proto=16 plen=8 crc)   <le u32 0> <be u32 flags>
```

Parse: u16@8 = 16 ≥ 7 → proto 16 → success; 16 ≥ 14 → flags =
ntohl(0x00000001), banner empty; subsequent commands use K2 and text
`"192.0.2.1|<ts>|super|super|1"`.

## 9. Identity (cmd 0x16; legacy fallback cmd 0x01 when proto < 8) (VERIFIED-live)

Read-only. One packet, one reply (observed ≈ 3.2 KB on M64_VL40). The
reply payload is **one large INI-ish text blob**, in this order:

```
[MinerInfo]
Key = Value            lines ("\n"-separated, spaces around '='; e.g.
                       MinerType, ControlBoardType, ControlBoardVersion,
                       HashBoardVersion, PowerType, FirmwareVersion,
                       ChipData, is_btrom, MinerSn, …)
#<MAC>#                 record separators of the form "#...#"
[PowerInfo]            power block (PowerName, PowerRevision, …)
#web_pool=1,sshd=0#     daemon/feature switches
#super=255 user1=0 user2=0 user3=0#   8889 permission bitmap (§5)
SUMMARY,...             cgminer-style CSV sections:
|EDEVS,...|ASC=n,...    SUMMARY / EDEVS / POOLS / #Uptime=…
|POOLS,...|POOL=n,URL=...
#Uptime=...,PowerRT=...
```

- The static-RE prediction "5 NUL-separated ordered fields, then
  `#`-records" (handler FUN_00468960) is **DISPROVEN as the primary
  structure** on this firmware: the blob does not cleanly delimit into 5
  fields. Robust clients key off the `Key = Value` lines, not positional
  NUL fields. (`client/proto.py:parse_identity` still splits defensively;
  selection-relevant values — `is_btrom`, `ControlBoardType`, absent
  `PlatformVersion` → v2 — come from the key lines and defaults.)
- Redacted real capture:
  [appendix/identity-2026-10-15-redacted.txt](appendix/identity-2026-10-15-redacted.txt)
  (structure reference; serials/MACs/pool users redacted — keep it that
  way).
- Upgrade use: feed `ControlBoardType` (lowercased), `ChipType`/chiptype
  (empty → `"0"`), `PlatformVersion` (absent → `v2`) and `is_btrom` into
  the selection key of 03. This miner resolved to **`0-h616v2`**.

## 10. Firmware bulk upload (VERIFIED-tool: FUN_004793c0 + FUN_00478b30)

After the cmd 0x07 packet is sent (on its own connection, K2-encrypted
when proto ≥ 14):

1. `setsockopt(SO_SNDBUF = 0x1000)`.
2. Send **u32 LE total size**, then the **raw sub-image bytes** (as stored
   in the bundle — still encrypted, see 02) in **1024-byte** chunks.
   No per-chunk framing, no AES. Same socket.

   *(ctx+0x2c84 flag switches to larger unchunked writes — legacy path,
   UNVERIFIED; 1024-chunking is the modern default.)*
3. Afterwards wait for the echoed cmd-7 reply (result code) with a
   **100 s** recv timeout (FUN_0047db90 selects 100 s when cmdcode == 7,
   else 10 s). Result 0 = miner accepted the image into staging.

## 11. Upgrade-status polling (VERIFIED-tool: FUN_00467810)

- Requires proto ≥ 7.
- Request: cmd 0x15, envelope text, fresh connection per poll (hello on
  its own connection first).
- Reply payload is ASCII: contains `upgrade=`, value compare is a
  substring search: contains `success` → done-ok; contains `failed` →
  failed; otherwise still in progress (payload doubles as progress text).
- Recv timeout 10 s per attempt.

## 12. Legacy framing (proto < 4) — context only

FUN_0047d240 (used when the version probe returns 0): raw socket payload
`"MT99"` + be16(len_auth) + be16(len_config) + auth-string + config-string,
where the config ends with `;/usr/bin/upgrade.sh` (default when the dialog
config field is empty); auth line is built from password ("root" default
vs stored; version-gated by constant 0x133F081 = 2024-06-14-ish build no.)
via FUN_00499b30. Then a 4-byte `"MT03"` marker prefixes the same
FUN_004793c0 raw firmware stream. Not needed against any proto ≥ 4 miner.

## 13. Protocol-version gates (VERIFIED-tool)

| gate | effect |
|---|---|
| ≥ 14 | K2 for all post-hello commands (else K1); hello reply carries flags; envelope gets `\|hexflags` |
| ≥ 8  | identity via 0x16 (else 0x01) |
| ≥ 7  | hello u16@8 = proto directly; status poll 0x15 available; bulk download 0x14 available |
| ≥ 6  | modern upload prepare/stream flow (else FAIL) |
| ≥ 15 | skips an extra intermediate stage (FUN_00478890) when ctx+0x3520==1 |
| ≥ 12 | dispatcher FUN_00469900 picks newer helpers (004762e0 vs 0045f140) |
| ≥ 10 | package-type 2 (combined-bundle current flow), 6..9 → 1, <6 → 0 |
| ≥ 4  | new upgrade flow (FUN_00478b30); 0..3 → legacy MT99/MT03 flow |

## 14. Other listeners on the miner (orientation)

- **4028**: legacy cgminer-ish JSON API (v2: `summary`, `pools`,
  `get_version`, …) — what most integrations use; unencrypted.
- **4433**: v3 JSON API (`get.device.info`, `set.*` with token auth;
  independent of 8889 key material). Details: official apidoc zip at
  `vendor/api3/`; client reference `client/v3fw.py`.
- **80/443**: LuCI web UI (own credential store; `admin:admin` default).
- Tool's update-check server baked into the network ctor:
  `39.104.27.132:8802` (FUN_0040dd50) — internet-side, not miner-side.

---
Live-confirmed against M64_VL40 fw 20250409.15.REL, 2026-10-15.
