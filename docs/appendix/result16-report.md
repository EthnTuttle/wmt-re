# Audit: cmd-0 (hello) reply with "+8 field = 16", 8-byte payload — what does it mean?

Continuation of `/tmp/opencode/hello-audit-report.md`. Evidence = Ghidra disasm/decomp of
`wmt925.exe` (addresses cited) + string bytes verified against the exe.

## TL;DR

**The u16 at reply+8 of a cmd-0 reply is not an error code — it is the daemon's protocol
version.** WhatsMinerTool reads any value >= 7 as the proto version directly. Your
"result 16" reply = **a successful hello advertising proto 16 (0x10)**. The tool accepts
it on the first attempt (no retry, no dialog), stores flags from the payload, and proceeds
with proto>=0xe semantics (new AES key slot + `|<flags hex>` envelope field) for all
subsequent commands. The 8-byte payload is the modern hello reply body with an empty
banner: `[u32 legacy-proto slot][u32 flags (big-endian)]`.

There is **no result-code string for 16 anywhere in the binary** because result codes are
only consulted for cmds other than 0 — and 16 (=proto 16) never reaches that path.

---

## Q1 — Result-code → string table (FUN_00467a70 @ 00467a70, size 1852)

Complete and final. Switch is on `*(short*)((int)reply + 8)` (net3.c:1084, disasm verifiable
at 00467ab6+). Every case builds a bilingual message (English literal + GBK Chinese literal)
and returns it as a status string via FUN_004787f0 (a CString concat helper, NOT a dialog):

| code | English string | address | Chinese (GBK) | address |
|------|----------------|---------|---------------|---------|
| 0 | (none; builds `"成功"` "Success", returns 0) | 0x691e40 @00467ad1 | | |
| 2 | `"NetPacket Error"` @00467b02 | 0x6ab37c | `"网络包错误"` | 0x6aaf2c |
| 3 | `"Invalid Command"` @00467be0 | 0x6ab37c† | `"非法命令"` | 0x6ab38c |
| 4 | `"Data Error"` @00467cc4 | 0x6ab398 | `"数据错误"` | 0x6ab3a4 |
| 5 | `"Incorrect Password"` @00467da8 | 0x6ab3b0 | `"帐号密码错误"` | 0x6ab3c4 |
| 6 | `"No Permission"` @00467e8c | — | `"没有权限"` | 0x6924a8 |
| 7 | `"Miner Sys Error"` @00467f70 | 0x6ab3d4 | `"系统错误"` | 0x6ab3e4 |
| 9 | `"Need change pwd"` @00468054 | 0x6ab3f0 | `"未更改密码"` | 0x6ab400 |
| **default (1, 8, 10, 11, …, 16, 17+, all unlisted)** | **nothing — falls to `switchD_00467ac5_caseD_8`, returns 0 silently** | | | |

Code 1 has no case either. **`"Need change pwd"` is result 9, not 16.** String-table sweep
(0x6aad00–0x6ab500, plus `strings` for pwd/denied/change/version/support) shows no other
error-code strings that could correspond to 8 or >=10.

Crucially, FUN_00467a70 is only reached from `CMinerInterface::HandleRpcReplyData`
(FUN_00469210) **for cmds other than 0, 1, 0x13, 0x16** (net2.c:102-127: switch on cmd at
004692f5+: cmd 0 → FUN_004681d0, cmd 1 → FUN_00468730, cmd 0x13/0x16 → FUN_00468960,
else → FUN_00467a70). **cmd-0 replies never get result-string treatment at all.**

`HandleRpcReplyData` returns 0 ("valid packet") for every reply whose magic/cmd-echo/(low16
CRC) check passes — even error-result ones; it returns -1 only for a malformed packet
(00469496).

## Q2 — FUN_004681d0 @ 004681d0 (hello reply handler) — complete walk

Reply struct layout (all offsets from decrypted reply start; [ESI] = reply):

```
+0x00 u32 magic 0x7f7f5a5a        +0x0a u16 datasize
+0x04 u32 cmd echo                +0x0c u32 crc (low16 check)
+0x08 u16 proto/result            +0x10 payload…
```

Decision tree (disasm-verified, /tmp/ghs/auditc.txt):

1. **0046827f–00468292 — proto extraction:**
   ```
   v = u16 @reply+8
   if (v >= 7)                    proto_val = v                 // 00468288 MOV EDI,EAX
   else if (u16 @reply+0xa > 0)   proto_val = u32 @reply+0x10   // 00468292 (legacy)
   else                           proto_val = 0
   map[0] = sprintf("%d", proto_val)      // fmt "%d" @0x69168c, CALL 004093b0 @0046829f
   ```
   (The decompiler's `result < 7 && ...` blurred this; the disasm is unambiguous: JC at
   00468286 selects the >=7 path which keeps EDI = v.)
2. Session/field map insertion (std::map node alloc FUN_004b3c32, insert FUN_00409cd0)
   of key 0 = proto string, 004682c6–00468352.
3. **00468373: `CMP word ptr [ESI+8], 0xe; JC 0x004686be`** — if v < 14: skip to epilogue.
   (Mirrors the envelope side: `|%x` flags field exists only for proto > 0xd.)
4. If v >= 14 (flags present):
   - 004683c9–004683e0: `flags = ntohl(u32 @reply+0x14)` (Ordinal_8 = ntohl);
     `map[1] = sprintf("%x", flags)`   (fmt "%x" @0x691318).
   - 004684b4–004684ba: `if (byte @reply+0x18 == 0)` → banner empty → map[2] = empty;
     else 004684d6: `map[2] = sprintf("%s", banner @reply+0x18)` (fmt "%s" @0x690fc8).
5. Epilogue LAB_004686be: builds out status string `"成功"` ("Success", @0x691e40, len 4),
   returns 0.

**For the observed reply (v=16, datasize=8):** proto_val = 16; 16 >= 0xe so
flags = ntohl(u32 @payload+4); byte @payload+8 is past the 8-byte payload (reads as 0 in
practice → empty banner). No error path exists for this input. **The "result" is never
checked in the hello handler** — the +8 u16 is consumed as the version, full stop.

### Caller chain / what the caller does with proto & flags

`HandleRpcReplyData` (FUN_00469210) cmd-0 case → FUN_004681d0, returns 0.
Then FUN_00464e70 @ 00464e70 (one-shot RPC: builder FUN_00476620 → recv/decrypt
FUN_00477e30 → FUN_00469210) extracts the map fields (disasm /tmp/ghs/dis10.txt:925+):

- 00465043–00465054: `map[0]` → `strtol(s,0,10)` (FUN_00649940) → `*param_3 = proto`
- 0046505e: `CMP EAX,0xe; JL` — only if proto >= 0xe:
  - 00465109–00465115: `map[1]` → `strtol(s,0,16)` (`PUSH 0x10`) → `*param_4 = flags`
  - and if param_5 != NULL: `map[2]` (banner) → compared to `""` (__mbscmp @004651cb),
    propagated when non-empty.

Retrier FUN_00463560 @ 00463560 (disasm confirmed, 10-attempt loop, EDI=0xa @0046358c):

```
004635c0  CALL FUN_00464e70(…, &proto_out=EBX, flags_out=[EBP+14], banner_out=[EBP+18])
004635c5  if (EAX == -1)  → FAIL immediately (no retry; builder/connect/recv error)
004635ca  if (*proto_out >= 1) → return 0   // SUCCESS
          else retry (up to 10 total) → return -1
```

So **proto = 16 → `*proto_out = 16 ≥ 1` → retrier returns success on attempt #1.**

Wrapper FUN_00469900 @ 00469900 (called by op dispatcher FUN_004abd10) is the proto-tier
gate (disasm /tmp/ghs/auditd.txt):

```
00469961  if (retrier == -1) return -1                      // (no dialog)
0046996f  if (proto < 0xc) {                                // 12
             mode==0: proto<4 → FUN_00476370; 4..11 → FUN_004789f0
             mode!=0: status="失败"("Failed" @0x691e48), return -1
          } else {                                          // proto >= 12
             switch (mode) { 0,1 → FUN_004762e0; 2,3 → FUN_0045f140;
                             default → "失败", return -1 }
          }
```

proto = 16 (>= 0xc) → the modern-op switch; modes 0–3 proceed (FUN_004762e0/FUN_0045f140,
the family login/token exchange that fills the persistent session incl. flags for the
envelope `|%x` field). No branch on any specific proto value above 12, no password-change
dialog, no abort.

## Q3 — Builder/retrier/op-dispatcher behavior after hello reply "+8=16"

- Builder FUN_00476620: unaffected by the reply.
- Retrier FUN_00463560: **success, no retry** (see 004635ca).
- Dispatcher: continues the operation. Downstream consequences of proto 16:
  - **Envelope** (FUN_004641b0): appends `"|%x"` flags field (proto > 0xd).
  - **Key select** (disasm 00476a45–00476a5c): `if (proto < 0xe || cmd == 0) → key @
    keyctx+0x18 (K1); else → key @ keyctx+0x1c` — i.e., with proto 16 all cmds **except
    hello** encrypt with the second key (K2 slot). cmd 0 always K1.
- Dialogs: **none**. The only failure strings in this path are `"失败"` ("Failed") when the
  retrier gives up or the mode is unsupported, and the FUN_00467a70 table (unreachable for
  cmd 0).

## Q4 — CMP …,0x10 near packet handling

Nothing keys on 0x10/16. The relevant thresholds in the reply path are: `7` (00468283,
proto-source select), `0xe` (00468373, flags/banner present in reply), `0xe` (0046505e,
propagate flags/banner to caller), `0xc` (0046996f, op-tier gate), `0xe` (00476a45, key
select), `0xd` (envelope flags field, in FUN_004641b0). The lone `PUSH 0x10` (00465109) is
`strtol(…, base 16)` for the flags hex string.

---

## Actionable reading for proto.py / the M64 exchange

A cmd-0 reply must be interpreted as:

```python
v      = u16_le(reply, 8)            # NOT an error code for cmd 0
datasz = u16_le(reply, 10)
proto  = v if v >= 7 else (u32_le(reply, 16) if datasz else 0)
flags  = ntohl(u32 @ reply+20) if v >= 14 else 0     # payload bytes 4..8, big-endian
banner = cstring @ reply+24  if v >= 14 else b""
# hello is OK iff proto >= 1
```

So `v = 16`, 8-byte payload = legacy-u32 + flags-u32, empty banner → **hello succeeded,
daemon speaks proto 16**. Continue with: envelopes `"<ip>|<ts>|user|pass|<flags:x>"` and
the proto>=0xe key (K2 slot, keyctx+0x1c) for all cmds != 0.

If the daemon actually required a password change, subsequent non-hello cmds would come
back with +8 = **9** ("Need change pwd" / "未更改密码") — that is the only pwd-change
signal in the binary, and it does not exist on the cmd-0 path.
