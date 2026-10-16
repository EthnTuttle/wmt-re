# 00 — Research journal: how the 8889 protocol was reverse-engineered

Narrative companion to the specs (01–06) and the HOWTO (07). This is the
*process* record: what we tried, in what order, what each failure looked
like byte-for-byte, and what each dead end taught us. Read it before
attempting a similar protocol — the specs tell you *what* the protocol is;
this tells you *how we found out*, including two full audit rounds that
were needed before a single byte got a useful reply.

Work happened 2026-10-13 → 2026-10-15 (static RE and first client over
10-13/10-14; live bring-up on the evening of 10-14 through the morning of
10-15). All live results were confirmed against one miner:
**M64_VL40 @ 10.0.0.104, fw 20250409.15.REL, 8889 proto 16.**

## Why

Goal: upgrade the miner's firmware `20250409.15.REL → 20260908.12`
**without** running MicroBT's WhatsMinerTool (Windows/MFC; would need
Wine) — i.e. reproduce the firmware-upgrade path from a Linux box with a
clean-room reimplementation. Clean-room = document formats/protocol from
independent observation (static RE of the tool + live observation of the
miner), then implement to the spec.

## Materials obtained and what each taught us

All under `/home/ethan/network/wmt-re/vendor/` unless noted.

- **WhatsMinerTool 9.2.5** (`WhatsMinerTool-customer.exe`, x86 MFC;
  extracted exe MD5 `62609e0755e1eb46471c7a6446989f18`). The ground truth
  for every 8889 behavior. Analyzed with **Ghidra 11.0.3 headless**
  (project `/tmp/ghproj`, disasm/decomp evidence dumps `/tmp/ghs/`).
  Function addresses cited throughout the docs refer to this binary.
- **WhatsMinerTool Operation Guide V2.3** (PDF; text extract
  `vendor/wmtguide.txt`). Two load-bearing facts: §6 (≈ line 504 of the
  extract) — *"The default password is the same as an account number"*
  (i.e. `super/super`, `user1/user1`, …); §7 — only `super` can configure
  permissions for `user1..3`, which later explained the observed
  `#super=255 user1=0 …#` permission bitmap.
- **Official WhatsMiner API 3.0 doc bundle** (`vendor/api3/`, captured
  from apidoc.whatsminer.com). Taught the v3 (port 4433) token formula
  `base64(sha256(cmd + password + salt + ts))[:8]`, that `set.*` writes
  accept **super/user1/user2/user3 only** (`admin` explicitly
  "deprecated"/unsupported), and the `set.system.update_firmware`
  choreography: init JSON → `{"code":0,"msg":"ready"}` → u32 LE total size
  + raw firmware bytes → final JSON confirm.
- **Firmware catalog JSON endpoint**
  (`www.whatsminer.com/renren-fast/app/supportfilesmenu/list`) — how the
  tool discovers available firmware; source of the two reference bundles
  below.
- **Two firmware bundles** (`whatsminer-all-20260908.12_….bin` and
  `whatsminer-all-20251209.16_….bin`). Reverse-engineered container →
  docs 01/02/03: header, 0x68-byte entry table, the pair of AES-256 keys
  *for the 8889 transport* (not for the images), selection keys. Both
  bundles cross-verified (same parser code parses both; all CRCs check).
- **M54/M64 SD recovery image** (`M54_M64_control_board_flashing.zip`).
  An Allwinner-style **IMAGEWTY** container. We carved members out by
  scanning for known magic offsets (carve-by-offset method: locate the
  image table, split members by recorded sizes) — useful for gaining
  shell-level artifacts, but **`rootfs.fex` is hardware-encrypted at
  rest** (SoC-bound key), so the 8889 daemon binary inside could not be
  extracted/read server-side. Dead end for daemon RE — everything about
  the daemon side therefore comes from the *client* binary + live probes.

## Static RE phase (2026-10-13/14)

Ghidra headless scripting over the exe produced, in order: the bundle
format (01), the sub-image format (02), the selection key logic (03), and
a first-pass 8889 spec (04) with framing, the CRC variant, AES-256-ECB
with three static keys, cmdcodes and result codes. A pure-stdlib Python
client (`client/`: `aes256.py` KAT-green vs FIPS-197, `bundle.py`,
`proto.py`, `wmtcli.py`) was written to the spec. Two spec details were
flagged as guesses at this point and later turned out **wrong**: the CRC
was first believed to cover header+payload, and the hello reply was
believed to be three text fields. Both were corrected by byte-diffing
before/while going live.

## The failure ladder (live bring-up, 2026-10-14 → 10-15)

Every rung below cost real time. Symptoms are quoted exactly so the next
person can recognise them.

### Rung a — every command returns result 2

**Symptom.** First live hello (and then any command) came back as a
16-byte error frame, payload length 0:

```
5a5a7f7f <cmd-le> 0200 0000 ffff0000
 magic     cmd      ^^^^  ^^^^  ^^^^^^^^
                     |     |     crc = 0x0000ffff = "don't bother checking"
                     |     payload length 0
                     result 2 = "NetPacket Error"
```

Decryption was fine (the frame parsed, magic/cmd-echo correct), framing
was fine — the *content* was rejected. **Lesson:** result 2 is the
daemon's *generic* reject. It does not tell you which layer failed
(envelope shape, credentials, permissions, content). Do not iterate on
the layer you happen to suspect; diff your bytes against a known-good
sender instead.

### Rung b — EOF on the second packet

**Symptom.** Pipelining hello + command on one socket (a natural thing to
try) produced a clean **EOF** when the second packet was sent.
**Lesson:** the daemon serves **one command per TCP connection**. The
real tool runs hello on its own connection, then each command on a fresh
connection, and re-hellos per operation (to refresh proto version and
session flags). `client/proto.py` (`_hello_once` + `_op`) mirrors that.

### Rung c — credential probing: a complete waste of an evening

**Symptom.** With result 2 everywhere, the obvious hypothesis was "wrong
password". Every stock candidate — `super/super`, `admin/admin`,
`root/root`, `user1/user1`, … — returned the identical result-2 frame.
**Lesson:** the credentials were never the problem; the *envelope* was
malformed, and result 2 cannot tell the difference (rung a). Brute-forcing
secrets against a generic reject is indistinguishable from a syntax error —
rule out syntax first. (`wmtcli.py probe` now exists for legitimate
hello-only credential checks.)

### Rung d — audit #1: the envelope's first field is the miner's own IP

Byte-diffing our hello against the tool's (Ghidra trace of
FUN_004abd10 → FUN_00469900 → FUN_00463560 → FUN_00464e70 →
FUN_00476620; full chain in
[appendix/hello-audit-report.md](appendix/hello-audit-report.md)) showed
the tool copies the **connect-target string** — the miner's own
dotted-quad IP — into the envelope's first field:

```
real tool:  "10.0.0.104|1759862400|super|super"
our client: "|1759862400|super|super"            ← result 2, always
```

After the fix: result 2 became **"result 16" + an 8-byte payload**.
Progress — but see rung e.

### Rung e — "result 16" is not an error

**Symptom.** The hello reply's header u16@8 read `16`, which we initially
logged as a new error code. **Audit #2**
([appendix/result16-report.md](appendix/result16-report.md)) walked the
hello-reply handler FUN_004681d0 and found the field is **overloaded on
cmd 0**: for value ≥ 7 it *is* the protocol version; retrier
FUN_00463560 treats any proto ≥ 1 as success; and with proto ≥ 14 the
reply additionally carries session flags = **big-endian** u32 @ payload+4
(`ntohl`) and a banner cstring @ payload+8. From then on all non-hello
commands switch to key K2 and append `|<flags as %x>` to the envelope.
Corrected parse:

```
proto = u16@8 if u16@8 >= 7 else u32 @ payload+0   # >= 1 ⇒ hello OK
flags = ntohl(u32 @ payload+4)  if proto >= 14
banner = cstring @ payload+8    if proto >= 14     # often empty
```

**Lesson:** before treating a reply field as an error code, check whether
the field is *overloaded per command*. There is no result-16 string
anywhere in the binary — a five-minute check that would have saved an
audit round.

### Rung f — identity works; the predicted layout does not

With the envelope fixed, cmd 0x16 returned a ~3.2 KB identity blob
(redacted capture:
[appendix/identity-2026-10-15-redacted.txt](appendix/identity-2026-10-15-redacted.txt)).
The static-RE prediction "5 NUL-separated ordered fields, then
`#`-records" (handler walks 5 C-strings by strlen) is **not what fw
20250409.15.REL emits** — the reply is one INI-ish text: `[MinerInfo]` /
`[PowerInfo]` blocks of `Key = Value` lines, `#...#` separators, then
cgminer-style `SUMMARY`/`EDEVS`/`POOLS` CSV. **Lesson:** robust clients
key off the `Key = Value` lines; positional parsing across firmware
versions is fragile. (The RE'd key table still told us exactly which keys
to expect — `is_btrom = 0`, `ControlBoardType = H616`, no
`PlatformVersion` → v2: selection key `0-h616v2`.)

### Rung g — the official v3 door was open the whole time

In parallel we probed the documented v3 API on 4433 (`client/v3fw.py`,
`probe` mode = init JSON only, nothing staged). `admin` failed *by
design* (unsupported for `set.*`); **`super/super` returned
`{"code":0,"msg":"ready"}`** for `set.system.update_firmware`. Plain
statement: for a user who only wants to flash official firmware, **v3 +
factory `super` is the simplest path** — the 8889 RE was still needed for
independence, for verification of what the tool actually does, and
because 8889 credentials are a separate store (if they are ever changed,
v3 keeps working and 8889 needs the new password).

## Account / permission model findings

- Every 8889 account's factory-default password is the account name
  (guide §6). The identity reply exposes the 8889 rights bitmap:
  `#super=255 user1=0 user2=0 user3=0#` observed — super has everything,
  sub-accounts nothing; `user1:user1` fails even though the password is
  "correct". Only `super` can grant permissions (guide §7).
- Result 9 ("Need change pwd") means the account must have its password
  changed once via the official tool before 8889 accepts it.
- 4028 (v2 JSON), 4433 (v3 JSON), 80/443 (LuCI web) and 8889 are
  **separate credential stores**; changing one changes nothing else.
- v3 writes accept only super/user1/user2/user3; `admin` is unsupported
  by design.

## Tooling lessons (meta)

- **Ghidra headless + parallel audit subagents works.** The two decisive
  breakthroughs (rungs d and e) came from asking focused audit questions
  against the disassembly ("what bytes does the real first packet
  contain?" / "what does the cmd-0 reply handler actually read?"), not
  from more live probing. Diff bytes against a known-good sender; diff
  semantics against the reply parser.
- **Early plausible guesses are the expensive kind of wrong.** Two
  red herrings burned time: assuming the packet CRC covers
  header+payload (it covers payload only — confirmed by re-reading the
  builder's `CALL FUN_00492860` arguments), and assuming the envelope /
  command string is assembled with `:`-style separators (it is `|`, from
  a single verified constant in the binary). Verify format beliefs against
  *constants in the binary*, not against what would be a sensible design.
- **Check field overloading before inventing error codes.** "result 16"
  was a version advertisement (rung e). If a code has no string in the
  binary's mapper, it probably isn't an error at all.
- **One live capture settles what ten hours of disasm only bounds.** The
  identity layout (rung f) was predicted with high confidence and was
  wrong in a way only a live read could show. Keep probes read-only, but
  run them early.
- Server-side binaries in the SD recovery image are (hardware-)encrypted
  at rest; when a daemon image can't be extracted, its behavior can still
  be fully pinned from client-side RE + exhaustive live probing.

## Where things stand (2026-10-15)

- **VERIFIED-live** on the reference miner: framing, CRC coverage, key
  schedule (K1 hello / K2 post-hello at proto ≥ 14), the auth envelope,
  hello semantics (proto 16, flags), result codes 0/2, identity reply
  structure, one-command-per-connection — docs 03/04.
- **VERIFIED-live** (successful upgrade run, same evening): the 0x07 bulk
  upload stream + 0x15 status-poll choreography (04 §10/§11, 05),
  cmdcodes 0x0D/0x14 — see the outcome section below.
- Reading list for the impatient: 07 (HOWTO) → 04 (8889 spec) → 03
  (selection) → 05/06 (upgrade, gates) → 01/02 (bundle formats).
  Evidence: `docs/appendix/`.

## Outcome (2026-10-15): the upgrade landed

1. **v3 whole-bundle path: accepted but not applied.** On fw
   20250409.15.REL (API 3.0.1), `set.system.update_firmware` on 4433
   accepted the full 45 MB `whatsminer-all-20260908.12` bundle (init
   "ready" → streamed → final `code 0`), but after the explicit reboot
   the miner still ran 20250409.15.REL: the boot applier skipped the
   combined container. Four new **Factory Error Codes 5130–5133
   timestamped at that reboot** corroborate the silent rejection.
   Recorded lesson: on that daemon, *final code 0 = bytes received, not
   version applied* — always verify `fw_ver` afterwards.
2. **8889 path: success.** cmd 0x07 prepare → 13,025,864-byte
   `0-h616v2` sub-image streamed in ~8.1 s → prepare-ack OK → cmd 0x15
   returned `upgrade=success` on the first poll; the miner rebooted
   itself. Post-reboot `get_version` reports `fw_ver 20260908.12.Rel2`
   (API bumped 2.0.5 → 2.2.3), hashrate and thermals normal.
3. **Image selection closed** (appendix/selection-report.md): the vendor
   tool independently resolves this miner to `0-h616v2`; the v2/v3
   suffix derives from the *firmware file name* tokens (FUN_0049c2f0),
   never from the identity blob, and `0-h616v3` is unreachable for
   `whatsminer-all-*` bundles. The clean-room kv-selection made the same
   choice as the tool, for reasons now documented.
4. Doc 03 updated with the filename-token provenance correction.

## Command surface mapped (2026-10-15, static only)

Enumerated the tool's full miner-facing command set: op dispatcher
FUN_004abd10 (25 arms via jump-table bytes), 24 GUI op-writes in
FUN_00492aa0, and the cmd-0x0d `K=V` key matrix (keys 1–28) — all in
docs/08-undocumented-cmdcodes.md with quoted disasm. New wire cmdcodes
beyond doc 04: 3 (MT09 board probe), 4 (accounts), 5 (perf mode), 6
(pools), 8 (reboot + MT10), 0xa/0xb (restore family), 0xc (web pools),
0x0e (3 named ints), 0x19 (upfreq); cmd 0x13's sender found
(FUN_0047dce0). Also documented: UDP 8888 listener, 4028 probes, update
server 39.104.27.132:8802, and the tool's own default creds admin/F-0jk;
(settings dialog, not miner creds). Key lesson: the CFG-packer mangles
decompiles of the workers — decisive cmd/key immediates had to be read
from raw `PUSH imm` bytes (and jump-table arms from exe bytes), never
from decompiler output.

## Credit

Clean-room work by the project authors for **interoperability and
ownership** purposes: no MicroBT code is copied or distributed here; the
specs describe observed formats and behavior. Vendor documents quoted
(guide, apidoc) remain © MicroBT and are referenced, not reproduced, in
`vendor/`.

---
Live-confirmed against M64_VL40 fw 20250409.15.REL, 2026-10-15.
Upgrade run outcome live-confirmed same day: miner now runs 20260908.12.Rel2.
