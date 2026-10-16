# Audit: why does the miner (M64_VL40 @ 10.0.0.104) reject every command with result 2?

Clean-room byte-diff of WhatsMinerTool 9.2.5 (`wmt925.exe`) first-packet (cmd=0 hello)
vs `~/network/wmt-re/client/proto.py`. Read-only analysis; evidence = Ghidra disasm/decomp
addresses + verified string constants in the binary.

## Verdict (ranked diffs)

### #1 — DEFINITIVE: hello `text` field

**The real tool sends the miner's own IP address string as the envelope `text` field.
proto.py sends empty text.**

- Real tool envelope (plaintext, before AES-K1):
  `"10.0.0.104|<unixtime>|super|super"`
- proto.py (`Miner._send` cmd==0 path → `wrap_command(b"", ...)`):
  `"|<unixtime>|super|super"`

Everything else in the packet (header, envelope field order, separators, formats,
keys, crypto) is byte-identical. A daemon-side check on the first (text) field fully
explains result 2 = "NetPacket Error" for every command from proto.py.

### #2 — Secondary (post-dates the failure): hello reply parse

proto.py parses the hello reply as NUL-separated text. The tool's parser
FUN_004681d0 reads **binary**: u32 LE proto-version @payload+0, u32 flags @+4
(printed `%x`), banner cstring @+8. proto.py's `struct.unpack_from("<I")` fallback
recovers the version, but `session_flags` will silently stay 0. Harmless until the
hello passes; matters for proto>=0x0E envelopes (`|%x` field).

### #3 — Cosmetic: retry count

Tool's hello retrier loops up to **10** attempts (`MOV EDI,0xa` @0046358c,
decrement loop 00463598–004635d1). proto.py uses 3. Irrelevant to result 2.

---

## Byte-exact first-packet template (real tool)

Plaintext header (16 bytes), little-endian:
```
offset  size  value
0x00    4     5a 5a 7f 7f            (magic u32 0x7f7f5a5a)
0x04    4     00 00 00 00            (cmdcode = 0, plain u32)
0x08    2     len1 = len(envelope)   (u16)
0x0a    2     00 00                  (len2 = attach len = 0)
0x0c    4     crc32(payload)         (init 0xFFFFFFFF, NO final xor)
```
Payload = envelope = `"<miner IP as dotted quad>|<unixtime>|super|super"`
(e.g. `"10.0.0.104|1759862400|super|super"`).

Whole `header+payload` pkcs-aligned to 16, AES-encrypted with **K1** (key installed by
FUN_00469510 from .data @0x7254c0 → ctx+0x18; cmd==0 forces K1 regardless of proto),
sent in one `send()` on a **fresh TCP connection to port 8889** per command.

proto.py emits the same shape except `text=""` → envelope starts with `|` and len1/crc
differ accordingly.

---

## Per-question answers

### 1. Hello text field
**= miner record field 0 = the target miner's own IP string** (the same string the tool
passes to `inet_addr()` when connecting).

Evidence chain:
- FUN_004abd10 (per-miner op dispatcher) loop: 004abd99 `CALL FUN_0049bfb0` (record
  iterator) → `MOV EDX,[EAX]` @004abd9e → record+0 CString **assigned** into the local
  text CString (refcount-sharing operator= path, 004abdcf–004abde5). Guard: skip when
  `strlen==0` (`CMP dword ptr [ESI+-0xc],0` @004abe26).
- Case ctx+0x2970==1 → 004abe85–004abeb3: pushes `[ctx+0x328c]`, text-copy, ctx →
  `CALL FUN_00469900` @004abeb3. (`ctx+0x328c` ∈ {0,1} lands in an unused parameter
  slot; see #2.)
- FUN_00469900: `MOV ESI,[EBP+0x8]`… pushes text copy, ctx → `CALL FUN_00463560`
  (retrier) @0046995c.
- FUN_00463560 → `CALL FUN_00464e70` @004635c0 (text passed trough @004635bb).
- FUN_00464e70 → `CALL FUN_00476620` (builder) @00464ef7. Param map (from builder
  decomp + push analysis): param_1=ctx=`[EBP+8]`, param_2=text, param_3=cmd,
  param_4/5=attach/len, param_6=outlen, param_7=session.
- Builder FUN_00476620: connects with `inet_addr(text)` — `ADD EAX,-0x10/PUSH` of its
  param_2 then `CALL FUN_00461eb0` @00476904 (connect helper, net12.c;
  `Ordinal_11(param_2)` = inet_addr). So text == the connect target IP.
- Builder then passes text into envelope FUN_004641b0 → first `|`-field.

All family-switch cases (ctx+0x2970 = 0,1,2,…,0x18) copy the same `iVar10` record-field
string as text before dispatch, so this holds regardless of detected miner family.

### 2. enc type/key + claimed proto version in the hello
- **cmdcode = 0 hardcoded**: FUN_00464e70 pushes a constant 0 into the builder's cmd
  slot (`PUSH 0x0` @00464ed9, one of three zero pushes for cmd/attachlen/attach).
  The whole retrier→FUN_00464e70 path is hello-only; every other cmdcode (0x07, 0x0d,
  0x14, 0x15, 0x16/0x01, …) is emitted by direct builder callers with literal pushes
  (see cmdcodes.txt).
- **Key = K1 always for hello**: key select @00476a45–00476a5c:
  `CMP dword ptr [EBP-0x10],0xe; JC → +0x18` … `CMP dword ptr [EBP+0x10],0; JZ → +0x18`
  → cmd==0 (`[EBP+0x10]`=param_3=0) forces key @keyctx+0x18 = K1 regardless of proto.
- **No proto version is claimed** anywhere in the hello; cmd=0 IS the version query.

### 3. proto>=0x0E `|%x` flags field and ctx+0x355c
- Envelope builder FUN_004641b0 appends `"|%x"`(flags) (`%x` fmt @0x691318) only when
  `proto > 0x0d`, and `"|"+ctx+0x355c` only when that CString is non-empty. Hello runs
  with session-map param_7 = 0 (`PUSH 0x0` @00464ec2 = param_7) → no flags field.
- **ctx+0x355c default = empty CString**: context ctor FUN_0048e3b0 stores the
  MFC empty-string singleton there — `[vftable+0xc]` get-empty-data, `ADD EAX,0x10`,
  `MOV dword ptr [EBX+0x355c],EAX` @0048f05b–0048f063. No config/ini path writes it
  (FUN_0049fa90/FUN_004a0300 read all TOOL/POOLS/POWER ini keys; 0x355c untouched).
  → default flow has NO extra field. proto.py matches.

### 4. Envelope field order/format (FUN_004641b0)
```
text + "|" + "%lld"(unixtime) + "|" + user + "|" + pass
      [ + "|" + "%x"(flags)        ]               iff proto>0x0d
      [ + "|" + extra(ctx+0x355c)  ]               iff extra non-empty
```
Verified constants: sep `"|"` @0x6aac88; time fmt `"%lld"` @0x6aaf14; utc unix seconds.
Credentials at runtime: user = ini `[SETTING] AccountName` default `"super"` (@0x6ad284);
**password is copy-assigned from the username** @004a0401–004a041b (one-shot global
guard @0x733018) → default super:super. proto.py matches (modulo #1 text).

### 5. Pre-hello sequence / I/O pattern
- Fresh, non-blocking TCP connect per command, port 0x22b9 (`PUSH 0x22b9` @004768df;
  connect helper FUN_00461eb0 = socket/connect/select). No TCP_NODELAY observed; no
  read-before-write, no extra 8889 pre-traffic.
- Hello retried up to 10× with fresh connect each round (retrier loop @0046358c+).
- Separate miner-family detection does connect/send an `"MT14"` probe and a
  cgminer-style `"summary"` probe (str @0x692408) — on the cgminer API port, not 8889,
  and not part of the 8889 hello exchange.
- proto.py already does one-connection-per-command (docstring in `_hello_once`/`_op`).

### 6. Result-2 semantics
- FUN_00467a70 maps result 2 → display string `"NetPacket Error"` only. No tool-side
  logic reveals server-side conditions. Client's own reply validator FUN_00469210
  (`CMinerInterface::HandleRpcReplyData`) checks magic 0x7f7f5a5a, cmd echo == request,
  and **low-16 bits of CRC** over payload only when the stored crc's high 16 bits are 0
  (00469210: `(param_3[3] & 0xffff0000)==0` gate).
- Conclusion: result 2 is the daemon's generic "reject"; with diff #1 in place the
  daemon almost certainly validates the first (text/IP) field of the envelope.

### 7. Other send-path anomalies
- None besides #1 on the send path. Header layout, len1/len2 semantics, CRC
  (init 0xFFFFFFFF, no final xor — brief's "header+payload" claim was wrong; CRC covers
  payload only, `CALL FUN_00492860` args @00476a17–00476a22), 16-alignment+pad, AES-K1
  for cmd 0 all verified identical to proto.py.
- Reply-side: hello reply is `u32 proto | u32 flags | cstring banner` (FUN_004681d0),
  see diff #2.

## Remaining blind spots
- Session-map internals (proto/flags caching after a successful hello) — irrelevant
  until hello passes.
- Whether the daemon accepts only its *own* IP vs the *client* IP in the text field —
  in the tool these coincide on the wire (it sends the record's IP). Try text =
  target miner IP first (matches tool bytes exactly); if still result 2, test text =
  local client IP.
- rootfs.fex (still encrypted; not openable with K1/K2/K3) — likely a separate
  firmware-file key; unrelated to the 8889 failure.
