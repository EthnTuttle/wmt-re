# 07 — Interrogating your own miner (HOWTO)

Audience: technical WhatsMiner owners who want to query (or upgrade) their
own machines without the Windows-only WhatsMinerTool. Everything here was
confirmed live against an M64_VL40 running fw 20250409.15.REL (8889 proto
16) on 2026-10-15. Specs: 04 (8889 wire protocol), 03 (identity → firmware
selection); working client: `client/`; story of how this was found: 00.

## Start here: try the official v3 path first

If your goal is simply "query my miner" or "flash the firmware I
downloaded from MicroBT", you probably do **not** need the 8889 protocol
at all. The miner also listens on TCP **4433**, a documented JSON API
(v3, see `vendor/api3/` — MicroBT's own apidoc bundle):

- Read-only `get.*` commands need no authentication, e.g.
  `get.device.info` — including `param="salt"`.
- Write `set.*` commands need a token:
  `base64(sha256(cmd + password + salt + ts))[:8]`, with `salt` from the
  unauthenticated call above. Accounts accepted for writes: **super,
  user1, user2, user3 only — `admin` is explicitly unsupported**
  ("deprecated"). Factory-default password for every account is the
  account name itself.
- Firmware update over v3 is `set.system.update_firmware`: send the init
  JSON → expect `{"code":0,"msg":"ready"}` → send u32 LE total size +
  raw firmware bytes → final JSON confirm. A working prober/uploader is
  `client/v3fw.py` (modes `probe` / `run`); `super:super` init-probed OK
  live on the reference miner.
- The v3 API accepts the **whole `whatsminer-all-*.bin` bundle** — no
  sub-image selection homework required miner-side.

The 8889 work documented here exists for verification and independence
(and because 8889 credentials are a *separate* store if they are ever
changed). But for a one-off firmware bump, v3 + factory `super` is the
simplest path.

## Port / daemon map

| port | service | what it is |
|---|---|---|
| 8889 | `/usr/bin/api` | binary "NetPacket" protocol used by WhatsMinerTool — the subject of 04 |
| 4028 | cgminer-ish JSON | legacy v2 API (`summary`, `pools`, `get_version`, …); plaintext; what most monitoring integrations use |
| 4433 | v3 JSON API | framed JSON (u32 LE length prefix); `get.*` open, `set.*` token-gated; docs in `vendor/api3/` |
| 80/443 | LuCI web UI | own credential store; factory default `admin:admin` |

These are **separate credential stores**. A password you changed in the
web UI does not change the 8889 account password, and vice versa.

## Read-only probes vs state-changing commands

Safe probes (we ran all of these against a production miner):

- **8889** cmd `0x00` (hello), cmd `0x16` (identity; `0x01` on proto < 8),
  cmd `0x15` (upgrade-status poll — read-only status text).
- **4028** v2 `get_*` JSON (`get_version`, `summary`, `pools`, …).
- **4433** v3 `get.*` JSON (`get.device.info`, `get.system.setting`, …).

**Change state — do not send casually:**

- **8889** cmd `0x07` (firmware prepare + raw bulk stream — stages an
  image; miner applies after verify and reboots itself), cmd `0x0D`
  ("set", e.g. attachment `3=1` pre-flag), cmd `0x14` (makes the daemon
  produce/package data, e.g. log archives).
- **4433** any `set.*` — including `set.system.update_firmware` after the
  init handshake returns `"ready"`.
- The LuCI UI's own actions, obviously.

## The 8889 auth model (read this before writing a client)

Every 8889 command's text is an envelope, not a command string:

```
<miner's own IP>|<unixtime>|<user>|<pass>[|<session flags as %x>]
```

- The first field is the **target miner's own dotted-quad IP** — the tool
  reuses the connect-target string. If this field is empty or wrong you
  get **result 2 on everything, even with perfect credentials**.
- Factory defaults: password == account name (`super/super`,
  `user1/user1`, …), per MicroBT's own operation guide.
- `|<flags>` is appended only when proto ≥ 14; the flags value comes from
  the hello reply (04 §8).
- Rights are per-account and visible in the identity reply:
  `#super=255 user1=0 user2=0 user3=0#` means super has full 8889 rights
  and the sub-accounts have **none** — a default-configured miner rejects
  `user1:user1` on 8889 even though the password is "correct". Ask `super`
  to grant permissions (official tool) if you need a less-privileged
  account.
- Result 9 = "Need change pwd": the account's password must be changed
  once via the official tool before 8889 accepts it.

## Minimal recipe (hello + identity in Python)

Use the reference client (pure stdlib Python 3, no dependencies);
`client/proto.py` implements 04 exactly — framing, payload-only CRC variant,
AES-256-ECB key schedule, envelope, one-command-per-connection:

```sh
cd client
python3 wmtcli.py --host <miner-ip> hello       # proto version + session flags
python3 wmtcli.py --host <miner-ip> identity    # full identity blob + selection inputs
python3 wmtcli.py --host <miner-ip> poll        # upgrade status (read-only)
```

Credentials default to `super`/`super`; override with `WMT_USER` /
`WMT_PASS` or `--user/--passwd`. There is also `wmtcli.py probe`
(hello-only against stock-cred candidates) and `wmtcli.py raw --code N`
(allowlisted read-only cmdcodes, dumps the raw reply). For v3:
`WM_FW_PASSWORD=… python3 v3fw.py --host <miner-ip> --account super probe`
(init handshake only, nothing staged; default `--account admin` fails for
firmware writes by design) and `... setting` (read-only
`get.system.setting`).

Do not reinvent the envelope, the key schedule, or the one-connection rule
— they are the three places everyone burns time (see the debugging matrix).

## Result codes (8889, non-hello commands)

| code | meaning | usual cause |
|---|---|---|
| 0 | success | — |
| 2 | NetPacket Error | generic reject: envelope text not the miner IP, wrong creds, or disallowed content |
| 3 | Invalid Command | cmdcode unsupported by this daemon |
| 4 | Data Error | payload rejected (e.g. wrong sub-image for this board) |
| 5 | Incorrect Password | auth failed |
| 6 | No Permission | account lacks the right (see the `#super=…` bitmap) |
| 7 | Miner Sys Error | daemon-side failure |
| 9 | Need change pwd | password must be changed via official tool first |
| other | unmapped | the tool itself has no string for it — treat as failure and capture bytes |

On **cmd 0 (hello) the "result" field is the protocol version**, not an
error code: ≥ 7 means the value is the proto version directly, and any
proto ≥ 1 means the hello succeeded.

## Debugging matrix (each row cost us real time)

| symptom | actual cause | fix |
|---|---|---|
| result 2 on **every** command, error frame `plen=0`, `crc=0x0000ffff` | envelope text field not set to the miner's own IP — or wrong creds; result 2 is a *generic* reject that cannot distinguish layers | set text to `<miner-ip>\|<ts>\|<user>\|<pass>`, then re-test creds |
| "result 16" on hello | not an error: miner advertises **proto 16**; ≥ 1 = success | read u16@8 as the version; parse flags (BE u32 @ payload+4); switch to K2 + `\|flags` |
| clean EOF when sending a 2nd packet on one socket | daemon handles **one command per connection** | fresh connect per command (hello on its own connection first) |
| result 9 | account flagged must-change-password | change it once with the official tool (or another permitted channel) |
| result 6 with "correct" default password (e.g. `user1`) | account has zero 8889 rights in the permission bitmap | use `super`, or have super grant permissions |
| identity parse yields garbage when splitting on NUL | fw ≥ 20250409 sends one INI-ish blob, not 5 NUL fields | parse `Key = Value` lines (04 §9) |
| v3 `set.*` rejected for `admin` | admin unsupported for v3 writes by design | use super/user1/user2/user3 |

## Safety notes

- Miners are **heaters and expensive hardware**. An upgrade means
  downtime (minutes to tens of minutes) plus a self-reboot; plan the
  window. If the miner heats your home, check the weather first.
- **Upgrades are one-way**: MicroBT states no rollback once on
  20260908.12 (secure-boot chain). Treat every flash as permanent.
- Sub-image choice must match the board: chiptype / platform /
  PlatformVersion (v2/v3) / btrom (03). A wrong pick should be rejected
  miner-side (result 4); do not test that theory casually.
- Capture and save the identity reply *before* changing anything; it is
  your ground truth for selection and for the permission model.
- Never log or commit credentials; pass them via env (`WMT_USER` /
  `WMT_PASS`, `WM_FW_PASSWORD`).

---
Live-confirmed against M64_VL40 fw 20250409.15.REL, 2026-10-15.
