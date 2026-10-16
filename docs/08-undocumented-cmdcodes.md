# 08 — Full miner-facing command surface of wmt925.exe (undocumented cmdcodes)

Static enumeration of every command WhatsMinerTool 9.2.5 can send to a
miner, complementing doc 04 §6 (which covers the cmdcodes live-verified in
2026-10). Everything here is **VERIFIED-tool** from static analysis of
`wmt925.exe` (MD5 62609e0755e1eb46471c7a6446989f18); nothing in this file
was probed against a live miner. Method: the GUI writes an op code to
ctx+0x2970, a per-miner thread runs the dispatcher
`CWhatsMinerToolDlg::ThreadDoRemoteOperation` (FUN_004abd10, switch on
ctx+0x2970, jump table at file offset 0xac33c / VA 0x4acf3c — decoded from
exe bytes, so packer-junk-free), each op's worker builds an attachment and
calls the generic sender FUN_00478890 / FUN_004789f0, which envelope it via
the 8889 builder FUN_00476620 (see 04 §2). Decisive disasm lines are quoted
inline.

## 1. Sender plumbing (VERIFIED-disasm)

- `FUN_00478890(ctx, ip, attachCStr, cmd, ?, flags)` → `FUN_00476620`
  envelope → transact FUN_0047dc10. Special case at 0x4788f6:
  `CMP ESI,0x3 / JNZ … / CALL 0x00465600` — **wire cmd 3 runs the MT09
  board-config exchange instead of an envelope.**
- `FUN_004789f0(ctx, ip, attachCStr, cmd, ?, ?)` — same builder; cmd in EBX.
  Special case at 0x478a53: `CMP EBX,0x8 / … / CALL 0x00465600` — **cmd 8
  also pre-runs the MT09 board-config exchange** (FUN_00465600 reads the
  miner's MAC + chip type and picks the h616v2/h616v3 parameter table).
- Most "set" ops are just `sprintf("<keyid>=<value>")` + cmd **0x0d**.
  Format strings: `%d=%d` @0x6aacc4, `%d=%s` @0x6aacbc.
- Proto gate: workers call FUN_0047d790 (~= hello via FUN_00463560 then
  negotiated-proto ≥ 4 → new path; else legacy/no-op). Hello retries 10×,
  fresh socket each time (FUN_00463560 → FUN_00464e70, cmd 0).

## 2. Op dispatcher, op value (ctx+0x2970) → worker → wire

Case→worker mapping read from the jump table bytes at 0x4acf3c (25 arms),
each arm's worker call verified against the arm body. "Menu" column pairs
the write of each op value (all writes are in OnCommand body FUN_00492aa0)
with the confirmation string that precedes it (VERIFIED-strings) where one
exists.

| op | menu pairing | worker | wire (VERIFIED-disasm unless noted) |
|---|---|---|---|
| 0 | "Confirm to reboot the miners?" | FUN_00477490 | **cmd 0x08** via FUN_004789f0 (`00477537: PUSH 0x8` … `CALL 0x4789f0`), then raw **`MT10`** 4-byte follow-up FUN_004775d0 |
| 1 | resume/suspend work, disable/enable btminer at boot | FUN_00469900 | tiered: key **8** (`FUN_004762e0: 00476319 PUSH 0x8 / CALL 0x47bb10` → `8=<0|1>`, cmd 0x0d) and key **27** (FUN_0045f140 → `0045f197 PUSH 0x1b`, fmt `%d=%d`, cmd 0x0d) |
| 2 | (no confirm; restore-miner family) | FUN_00477fb0 | **cmd 0x0b** via FUN_004789f0 (`00478021: PUSH 0xb`) |
| 3 | (no confirm; restore-factory family) | FUN_00478080 | **cmd 0x0a** via FUN_004789f0 (`00478127: PUSH 0xa`), then FUN_004781c0 raw follow-up |
| 4 | LED set (color dialog) | FUN_0047adf0 | cmd 0x0d, key **1**: `0047afc9 PUSH 0x1` fmt `%d=%s`, or `0047b02d PUSH 0x1` fmt `%d=%d`; value strings `'red 200 200 0\|green 200 200 0'` @0x6aacf0 / `'red 200 100 0\|green 200 100 0'` @0x6aad10 |
| 5 | heat mode dialog | FUN_0047ab20 | cmd 0x0d, key **13**: `0047acea PUSH 0xd` + fmt `%d=%s` with keyid 13 pushed as fmt arg; value = `'normal'` @0x6924dc / `'anti-icing'` @0x6aad30 / `'H'` @0x6915bc |
| 6 | — | FUN_0047b620 | **stub, returns -1** (37 bytes); op 6 unimplemented |
| 7 | sync time | FUN_0047b650 | cmd 0x0d, key **21**: `0047b77a PUSH 0x15` fmt `'%d=%s,%ld'` (`%Y-%m-%d %H:%M` string + unix time); refuses old fw (logs "固件版本过低") |
| 8 | "switch to high performance / low power / normal mode" | FUN_0047b100 | **cmd 5**, attachment `sprintf("%d", mode)` (fmt `'%d'` @0x69168c, `0047b1df PUSH 0x5`, `CALL 0x478890`); proto<4 fallback FUN_0047b2b0 (legacy raw TCP transaction — format unclear) |
| 9 | — | (default arm: FUN_004b1300 progress UI only) | **no worker — no-op** |
| 0xa | "enable/disable the web pools configuration" | FUN_0047a8d0 | **cmd 0x0c**, attachment `sprintf("%d", onoff)` (fmt `'%d'`, `0047a9ac PUSH 0xc`) |
| 0xb | "adjust the target frequency" | FUN_0045efc0 | cmd 0x0d, key **4**: `0045f085 PUSH 0x4` fmt `%d=%d`, `0045f0b6 PUSH 0xd`, `CALL 0x478890` |
| 0xc | (no confirm; progress caption "Starting") | FUN_004b1300 + FUN_00463830 | **cmd 0x14** via FUN_00463830 — file/data download from miner (04 §6; e.g. log tgz export) |
| 0xd | "Miner API Switch" Enable/Disable | FUN_0047aa90 → FUN_0047bb10 | cmd 0x0d, key **6** = MinerApiSwitch: `0047aac9 PUSH 0x6` then `0047bbb2/…` fmt `%d=%d`, `0047bbe6 PUSH 0xd` |
| 0xe | "Power Fast Boot Switch" Enable/Disable | FUN_00479480 → FUN_0047bb10 | cmd 0x0d, key **7**: same 139-byte wrapper as 0xd; key-imm byte at 0x4794b9 = `6a 07` |
| 0xf | (fast-boot dialog) | FUN_0047a5f0 | cmd 0x0d, fmt `%d=%s`, key **9** if ctx+0x1db0==0 else key **22** if ctx+0x1db4==0 (`0047a6c4 MOV EAX,0x9` / `0047a6d4 MOV EAX,0x16`); a third key **20** branch on ctx+0x1dac exists in the decomp trail |
| 0x10 | adjust power | FUN_00476180 | cmd 0x0d, key **14**: `00476253 PUSH 0xe` fmt `%d=%s` |
| 0x11 | set power limit | FUN_0047cf10 | cmd 0x0d, key **15**: `0047cfe3 PUSH 0xf` fmt `%d=%s` |
| 0x12 | adjust upfreq speed | FUN_004785d0 | **cmd 0x19** via FUN_004789f0 (`0047862f PUSH 0x19`) — direct cmdcode, not a key=val |
| 0x13 | restore miner setting | FUN_0047a490 | cmd 0x0d, key **18**: `0047a563 PUSH 0x12` fmt `%d=%s` |
| 0x14 | set NTP server | FUN_0047a770 | cmd 0x0d, key **19**: `0047a843 PUSH 0x13` fmt `%d=%s` |
| 0x15 | set time zone (DEDUCED name — dialog title not inline) | FUN_00479b40 → FUN_0047bb10 | cmd 0x0d, key **23**: key-imm byte at 0x479b79 = `6a 17` |
| 0x16 | set fast mining (DEDUCED name) | FUN_00463610 | cmd 0x0d, key **24**: `00463667 PUSH 0x18` fmt `%d=%d` |
| 0x17 | disable factory mode (DEDUCED name; identity key list has `DisableFactoryMode`) | FUN_00463720 | cmd 0x0d, key **25**: `00463777 PUSH 0x19` fmt `%d=%d` |
| 0x18 | disable upgrade (DEDUCED name; `DisableUpgrade`) | FUN_00476cb0 | cmd 0x0d, key **28**: `00476d13 PUSH 0x1c` fmt `%d=%d`, value ctx+0x1d88 |

(quick sanity: arm→case mapping was also cross-checked against the GUI
op-value writes `MOV dword ptr [EDI+0x2970],N` in FUN_00492aa0 — 24
distinct writers, matching 24 non-default arms.)

## 3. Wire cmdcodes — consolidated view

| cmd | status vs doc 04 | what it carries (evidence) |
|---|---|---|
| 0x00 | documented (04 §8) | hello |
| 0x01 / 0x16 | documented (04 §9) | identity, tiered by proto |
| 0x13 | **sender located** — 04 §6 marked it UNVERIFIED | FUN_0047dce0 issues two envelopes through FUN_00476620/FUN_0047db90: proto ≥ 5 → cmd 0x13 (proto < 8) else 0x16; proto < 5 → cmd 1 (call-site disasm in hunt evidence: `0047dd6d`/`0047ddc4` push lists) — superseded identity tier |
| 0x03 | **new** | MT09 board-config exchange via FUN_00465600 (MAC + chip type → h616v2/v3 table index), not an enveloped payload |
| 0x04 | **new** | account update: `sprintf("%d,%d,%d,%s%s%s")` (fmt @0x6aad8c) — 3 ints + 3 concatenated strings from the password dialog (user/old/new + account-class ints; exact int meanings format unclear). Builder FUN_0047bc70: `0047be1a PUSH 0x6aad8c`, `0047be4f PUSH 0x4`, `CALL 0x478890`; proto<4 fallback FUN_0047bf20 (format unclear) |
| 0x05 | **new** | performance mode: attachment = decimal int (`'%d'`), op 8 / FUN_0047b100 |
| 0x06 | **new** | pool configuration push. Builder FUN_00479510 (worker of scheduler type 3, FUN_004af400): `00479703 PUSH 0x6` … `CALL 0x478890`; payload contains pool lines; compares against `'SHA256(DGB/FB…)'` @0x6aab9c and coin tag `'DGB'` @0x6aada4 while assembling; legacy fallbacks FUN_00479600/FUN_004797a0 (format unclear) |
| 0x07 | documented (04 §10) | firmware prepare + bulk stream |
| 0x08 | **new** | reboot (op 0); pre-runs cmd-3-style board probe, then raw `MT10` follow-up on the same dial |
| 0x0a | **new** | op 3 (restore-factory family) via FUN_00478080 + follow-up FUN_004781c0 (raw read; format unclear) |
| 0x0b | **new** | op 2 (restore-miner family) via FUN_00477fb0 |
| 0x0c | **new** | web-pools-configuration switch: attachment decimal int (`'%d'`), op 0xa |
| 0x0d | partially documented (04 §6 shows only `"3=1"`) | generic key-set `K=V`; full key matrix in §4 |
| 0x0e | **new** | `sprintf("%s=%d,%s=%d,%s=%d")` (fmt @0x6aad78) — three *runtime-named* int fields, built by FUN_0047c3c0 (scheduler type 6 thread FUN_004af230); semantics unclear; legacy fallback FUN_0047c4c0 |
| 0x14 | documented (04 §6) | start-mining / data-download (op 0xc) |
| 0x15 | documented (04 §11) | upgrade-status poll |
| 0x19 | **new** | adjust upfreq speed (op 0x12) — direct cmdcode, no `K=V` |

Reply side: replies to the new cmds flow through the same dispatcher
(FUN_00469210); only cmds 0/1/0x13/0x16 have bespoke parsers — the rest hit
the generic result-code mapper (04 §7).

## 4. cmd 0x0d key-id matrix (the entire "set" surface)

All sent as `sprintf("%d=%d"|"%d=%s", keyid, value)` inside cmd 0x0d.
Names in parentheses come from menu titles (VERIFIED-strings) or the
identity parse-table string list FUN_00470e50 (DEDUCED where marked).

| key | wire name / meaning | op |
|---|---|---|
| 1 | LED pattern (int or `'red R G B\|green R G B'`) | 4 |
| 3 | `3=1` upgrade pre-flag (doc 04 §6) | — |
| 4 | target frequency | 0xb |
| 6 | MinerApiSwitch (menu "Miner API Switch") | 0xd |
| 7 | Power Fast Boot switch (menu "Power Fast Boot Switch") | 0xe |
| 8 | mining suspend/resume (DEDUCED) | 1 |
| 9 / 22 / 20 | BtminerFastBoot / CgminerFastBoot family (DEDUCED from identity strings) | 0xf |
| 13 | HeatMode value string (`normal` / `anti-icing` / `H`) | 5 |
| 14 | power value (adjust power) | 0x10 |
| 15 | PowerLimitSet (DEDUCED) | 0x11 |
| 18 | restore miner setting | 0x13 |
| 19 | NTP server | 0x14 |
| 21 | `<%Y-%m-%d %H:%M>,<unix>` sync time | 7 |
| 23 | time zone (DEDUCED) | 0x15 |
| 24 | BtminerFastMining (DEDUCED) | 0x16 |
| 25 | DisableFactoryMode (DEDUCED) | 0x17 |
| 27 | btminer auto-boot on/off (DEDUCED; menu "disable/enable btminer at boot") | 1 |
| 28 | DisableUpgrade (DEDUCED) | 0x18 |

## 5. Out-of-band channels the tool also speaks

- **Raw `MTxx` frames** (4-byte literals via `send()`, no 8889 envelope;
  same miner IP / cmd-channel dial path): `MT09` → FUN_00465600 (board
  config: MAC + chip type → firmware table index), `MT10` → FUN_004775d0
  (sent right after reboot cmd 8), `MT14`/`MT15` → FUN_004657e0 (+FUN_004663d0/
  FUN_00467000; worker-restart/shutdown family), `MT17` → FUN_00467290
  (long-buffer write), `MT03` → FUN_0047d240; literals `MT25` @0x6aad44,
  `MT16` @0x6aad9c also exist. Reply read = raw `recv` loop FUN_00477e30
  (0x2010 buffer). Payload layouts beyond the literals: format unclear.
- **UDP 8888 listener** (tool-side): FUN_00443a70 binds `SOCK_DGRAM` port
  `htons(0x22b8)` = 8888 and `recvfrom`s 0x7ff-byte datagrams in a loop —
  receiver for miner-broadcast IP reports. Companion strings for the
  reply/config side: `'IP::'`, `'::netmask::'`, `'::broadcastaddr::'`,
  `'::gateway::'`, `'::dns::'`, `'::enddns'` (parser FUN_00476b30, builder
  FUN_00462e00) — the Detect/Set-IP feature. Transport port of the push:
  format VERIFIED-tool, port not pinned (likely the 8888 discovery channel —
  DEDUCED).
- **cgminer-era API on TCP 4028**: FUN_004663d0 probes with plaintext
  verbs `'pools'` @0x6923f8, `'edevs'` @0x692400, `'summary'` @0x692408
  (and power nearby) — the tool still polls legacy v2.
- **Update server (not the miner)**: CNetworkInterface ctor FUN_0040dd50
  defaults host `"39.104.27.132"` port **8802** (0x2262); firmware-table
  downloads over FTP: `39.104.27.132:1021`, `47.253.93.0:1021`,
  `8.213.209.67:21` (FUN_00401000/FUN_00407270; `upgrade_tables.ini`,
  `test_speed`). INI parser FUN_0049ebe0 selects `FwInfo_h616v2` /
  `FwInfo_h616v3` sections by the MAC/chip table from the cmd-3/8 probe.
- **Scheduler** `ThreadStartOperationMain` (FUN_004aed00, keyed by
  ctx+0x327c from the 7-item operations dialog, mapping FUN_004aa1f0):
  type 2 → FUN_004b0220 (firmware-upload thread family, DEDUCED),
  3 → FUN_004af400 (pools push cmd 6, then FUN_0047c5f0 → FUN_0047ca00
  firmware-stream helper that references the tool-settings credentials),
  4 → FUN_004af060 (password push cmd 4 via FUN_0047bc70),
  5 → FUN_004abd10 (the op dispatcher above), 6 → FUN_004af230 (cmd 0x0e
  three-named-ints).
- **Hard-coded tool-settings defaults**: user `"admin"`, password
  `"F-0jk;"` — CSettingDlg ctor FUN_004886e0 (the GUI's own login
  defaults; also referenced by the firmware-stream helper FUN_0047ca00
  and the ini reader FUN_004a0300). Not miner credentials.

## 6. Notes on confidence

- All cmd numbers, key ids and format strings above are quoted from
  disassembly (VERIFIED-disasm). Worker bodies go through a CFG-packing
  obfuscator; where the decompiler collapsed, the key/cmd immediates were
  taken from the raw `PUSH imm` bytes directly (validated by reading file
  bytes, e.g. `6a 06`/`6a 07`/`6a 17` at the three FUN_0047bb10 wrappers).
- Marked DEDUCED: semantic names inferred from adjacent menu strings or
  the identity parse-table labels; the wire bytes themselves are VERIFIED.
- Marked format unclear: legacy proto<4 fallbacks and MT-frame payloads
  where the wire layout could not be pinned statically without guessing.
- Ops 6 and 9 are dead arms in this build.

VERIFIED-tool: static analysis of `wmt925.exe`
(MD5 62609e0755e1eb46471c7a6446989f18), addresses cited inline. No live
traffic was sent for this document.
