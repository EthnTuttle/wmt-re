# 05 — Firmware upgrade choreography (8889, modern flow)

Scope: the path taken by WhatsMinerTool 9.2.5 against a proto ≥ 14 miner
with a combined `whatsminer-all-*.bin` bundle. Legacy (proto < 4) differs
only in framing — see 04 §12.

## Entry points and preconditions (VERIFIED-tool)

GUI upgrade for one miner: `CWhatsMinerToolDlg::UpgradeFirmware`
(FUN_004b21c0) → per-miner worker (ThreadStartUpgradeFirmware chain) →
`DoUpgradeFirmware` (FUN_00498110). Refusals before any network traffic:

- already-upgrading / busy flags (ctx+0x329c, ctx+0x29b4)
- **"Power firmware upgrade is not supported. Use AirToLiquid"**
  (ctx+0x2a90 == 1 with main-fw flag clear)
- **"The liquid cooled firmware cannot be upgraded, please use
  AirToLiquid"** (ctx+0x2a95-ish flag set) — tool-side refusal, see 06
- login/list prechecks (FUN_00495e90 / FUN_004a6980)

## Wire sequence (VERIFIED-tool unless marked; connection model VERIFIED-live)

```
Connection model (VERIFIED-live, 04 §1): ONE command per TCP connection —
the daemon EOFs a second packet on the same socket. Every command below is
preceded by a hello on its own connection (fresh key regime + flags), then
runs on its own fresh connection. Every command's text is the auth
envelope "<miner-ip>|<unixtime>|<user>|<pass>[|<flags>]" (04 §5), shown
as "env" here.

1.  hello          cmd 0x00, text env (no |flags field)   (K1-encrypted)
    ← reply: proto N = header u16@8 (N≥1 = success — NOT an error code);
      when N≥14 also flags (BE u32 @ payload+4) + banner; below use K2 +
      env|flags (N≥14)
2.  identity       cmd 0x16, text env               (0x01 if N<8)
    ← reply: one INI-ish Key=Value blob (04 §9) → parse by key, not
      position → selection inputs
3.  select sub-image per 03 (offline, from local bundle)
4.  [optional]     cmd 0x0D, text env, attachment "3=1"
                   (only when GUI pre-flag ctx+0x3514 set; DEDUCED off for
                   a plain upgrade click — skip unless live capture shows it)
5.  prepare        cmd 0x07, text env
6.  bulk stream    u32 LE size; raw sub-image bytes, 1024-B chunks
                   (same socket as step 5; SO_SNDBUF=0x1000; no AES,
                   no framing)
7.  ← prepare-ack  echoed cmd 0x07, result code 0   (wait up to 100 s)
8.  close
9.  poll loop      cmd 0x15, text env (fresh hello + fresh connection
    each iteration)
    ← reply text: "upgrade=success" | "upgrade=failed" | <in-progress>
    until terminal; proto ≥ 7 required
```

- Step 1 handshake wrapper retries ≤ 10× (FUN_00463560).
- Step 5/6/7 = FUN_00478b30 → FUN_004793c0 → FUN_0047dc10/0047db90.
- Step 9 engine = FUN_004ad6d0 loop → FUN_00467810 per miner; the GUI
  records per-miner state/progress in FUN_0049b6d0-block records
  (byte+0xD flag, int+0x10 percent) — **DEDUCED** bookkeeping, not wire.
- Poll cadence: GUI-timer driven, exact interval **UNVERIFIED**
  (expect human-scale seconds; be kind — 3..5 s).
- Overall success = per-miner status string equals the GBK literal
  "成功" set by FUN_004b21c0 after FUN_0047d070 returns.

## Convert stage ("whatsminer*_NeedUpgradeAgain.bin")

VERIFIED structure: `LoadUpgradeConvertFwImages` (FUN_0049e250) reads
**tool-local** files `data\whatsminer<N>_NeedUpgradeAgain.bin` (small
table of variants), each a *single encrypted ih_magic image*; decrypts
them tool-side (FUN_004a6fa0) and registers them.
`DecideUpgradeConvertFw…` (FUN_004631f0, log: `"miner version miss, load
%s convert firmware"`) substitutes one for missing/old-version miners —
i.e. miners too old for a direct jump get flashed with the *convert*
image first (miner then self-upgrades; ".NeedUpgradeAgain" = miner asks
for round two afterward). Selection is driven by ini keys
(`FwConvertDate`, `H616SecureFw*`) and chip/firmware dates — exact
predicate **DEDUCED** (see 06 for the gate text).
For a miner already ≥ the convert date, step 3 picks the bundle entry
directly and no convert file is involved.

## Failure / abort semantics

- Any negative return from send/recv aborts that miner's worker cleanly
  (per-miner isolation; GUI marks it failed).
- Non-zero result codes (04 §7) abort immediately; codes 5/9 (password)
  mean the miner's 8889 auth state needs attention before retrying, and
  code 2 most often means the envelope text is wrong (04 §5).
- Mid-stream TCP failure → miner just never gets "prepare-ack"; no
  partial flash occurs miner-side (image applied only after full
  reception + verify — DEDUCED from ack-after-stream design).

---
Live-confirmed against M64_VL40 fw 20250409.15.REL, 2026-10-15.
