# WhatsMinerTool 9.2.5 — Combined-bundle sub-image selection ("0-h616v2" vs "0-h616v3")

Binary: `/tmp/ghproj/wmt925.exe` (imagebase 0x400000). All analysis read-only via Ghidra headless.

## Verdict (summary)

1. **The tool picks `0-h616v2`.** The miner's cmd-0x16 identity blob plays **no role** in the v2/v3 choice.
2. Identity keys parsed: MinerType, ControlBoardType, ControlBoardVersion, HashBoardVersion, ChipDataAll, FirmwareVersion, is_btrom. **"PlatformVersion" does not exist as a key** — the literal occurs exactly once in the binary, at 0x006ab4b5, inside DECIDE's own log-format string `"Input ChipTypePlatform:(%s), PlatformVersion:%s, ..."` (@0x6ab498). It is never parsed from the miner.
3. The `v2`/`v3` suffix of the *requested* key comes only from the **firmware file/list name** via `FUN_0049c2f0` (tokens `.v3./rel3` → `"v3"`; `.v2./rel2`/`NeedUpgradeAgain1|2` → `"v2"`; otherwise `""`). For a name without such token, suffix = `""`.
4. `FUN_00462240` (DECIDE) then, for `Platform=="h616"`, rewrites `""`/`"v1"` → `"v2"` (mode-0 branch, 0x462421–0x46245f) and indexes the static map at 0x732a34: `{"v1"→"0-h616", "v2"→"0-h616v2", "v3"→"0-h616v3"}` → target **`0-h616v2`**.
5. Fallback: if `0-h616v2` is absent from the bundle's section map, and the *original* suffix was `""`/`"v1"`, it retries map[`"v1"`] = `0-h616` (0x4627b5–0x462828); else it fails with `TargetChipTypePlatform: %s, not found in CombinedUpgradePlatform`.
6. Only a firmware **name** carrying a `v3`/`rel3` dot-token makes the tool request `0-h616v3`. Bundle sections keyed `...v3` (pi_version==3) exist per `FUN_004a7290` but are unreachable without that name suffix.
7. `ctx+0x8` ("mode") is read by DECIDE but **has no writer anywhere in 9.2.5** — dead legacy field; in practice 0, and even value 1 would only switch v2→v1 (POWER ALL PACKAGE), never to v3.
8. `ctx+0x2970` (family switch) is written only in `FUN_00492aa0` (values 0..0x18) and read only by dispatcher `FUN_004abd10`; it never feeds bundle-key construction. Hypothesis refuted.
9. The strings `M64`, `CB6V5`, `H3VV08` **do not exist as byte strings in the binary** (raw scan from 0x401000: no hits); `L40` has no selection-path compares; `H616-CB6V12` @0x6b21d8 has **zero xrefs** (dead string next to UI-format literals "V12"/" (000)").
10. `is_btrom=0` from the identity is also irrelevant: the `-btrom` map choice takes `Btrom` from the *firmware record* (FUN_0049a3c0 appends `-btrom` iff a record field == "1").

So for the blob MinerType=M64 / ControlBoardType=H616 / CB6V5 / L40 / H3VV08-24111317 / is_btrom=0 / no PlatformVersion: **requested key = `0-h616v2`** (the pi_version==2 section), with silent fallback to `0-h616`, never `0-h616v3`.

---

## Evidence

### A. Identity (cmd 0x16) parsing and consumers

- Handler chain: `FUN_00468960` (cmd 0x16/0x13) → `FUN_00470e50` → comma-split key=value parser `FUN_00476dd0`.
- Hardcoded identity key literals and their only consumers (xref table, this session):
  - `MinerType` @0x6aafac → FUN_00470e50 (parse) + FUN_004881d0
  - `ControlBoardType` @0x6aafb8, `ControlBoardVersion` @0x6aafcc, `HashBoardVersion` @0x6aafe0, `ChipDataAll` @0x6ab06c, `is_btrom` @0x6ab11c → FUN_00470e50 only
  - `FirmwareVersion` @0x6aac8c → FUN_00470e50 + FUN_00466cd0 ("does miner need upgrade" version compare)
- **None** of these consumers is connected to `FUN_00462240` (DECIDE), `FUN_0049c2f0` (VERSUF), `FUN_004a7290` (READCOMB), or the static maps 0x732a2c/0x732a34.
- Raw byte search (0x401000 up): `M64` → **0 hits**, `CB6V5` → **0 hits**, `H3VV08` → **0 hits**, `PlatformVersion` → 1 hit @0x006ab4b5 = interior of the DECIDE log format @0x006ab498. Defined-string scan agrees. The tool cannot compare values it has no literals for.

### B. DECIDE (FUN_00462240) — the selection function, and its inputs

Called from exactly two places (xref scan):
- `FUN_00478b30` (SendFirmWareToServerAndGetStatus, "SpecifyFirmwareFile"/ALL-包 path) at **0x478d39**, ctx = stack local [EBP-0x8c], param_5(outmode)=2 (`00478c9b: PUSH 0x2`), Bound="" (CString assigned from 0x690f60 empty string at 0x478ce4 block).
- `FUN_00462e00` (DecideFirmWareDataBufferAndSize, auto-upgrade) at **0x462f81**, ctx = embedded dlg field dlg+0x3414 (or +0x33c4), see FUN_00462e00 decomp: `iVar3 = 0x3414; if (param_3==0) iVar3 = 0x33c4; local_20 = dlg + iVar3`, gated on `ctx+4 != 0` ("combined bundle loaded" flag, written at 0x4a68b3 / 0x4a6a09 from `FUN_00499a40` = IsCombinedFirmwareFile, which checks file magic 0xAE640A3F).

Both callers build the two string inputs from the **firmware file/list entry**, not the miner:
```
00478c7f: CALL 0x0049a3c0   ; out [EBP-0x24] = ChipTypePlatform  (FUN_00478b30)
00478c92: CALL 0x0049c2f0   ; out [EBP-0x20] = Version suffix    (from fw name)
```
(FUN_00462e00 does the same at its 0x462ed9/0x462ee9 sequence.)

DECIDE prologue log proves the parameter meanings (fmt @0x6ab498):
```
00462464: MOV EDI,dword ptr [EBP + -0x34]   ; Bound (param_4)
...
0046247a: PUSH 0x6ab498   ; "Input ChipTypePlatform:(%s), PlatformVersion:%s, ChipType:%s, Platform:%s, Version:%s, Btrom:%s, Bound: %s"
0046247f: PUSH 0x6ab440   ; "CMinerInterface::DecideCombinedUpgradeFirmWareDataBufferAndSizeByChipAndPlatform"
```
param_2 (ChipTypePlatform) is split by '-' into parts 0/1/2 = ChipType [EBP-0x30] / Platform [EBP-0x1c] / Btrom [EBP-0x20] (FUN_004b4fb1 tokenize calls at 0x462336/0x462346/0x462356).

### C. Mode read (ctx+8) and the Version rewrite

```
004623b7: MOV EAX,dword ptr [EBP + 0x8]     ; param_1 = ctx
004623be: MOV EAX,dword ptr [EAX + 0x8]      ; mode = ctx+8
004623c1: CMP EAX,0x1
004623c4: JNZ 0x00462421
; --- mode==1: "POWER ALL PACKAGE" ---
004623c6..4623df: Btrom="", Bound=""
004623e4: PUSH 0x6aabe4  ; "v2"
004623ec: CALL 0x00643b94   ; stricmp(Version,"v2")
004623fa..462406: if equal -> Version = "v1" (PUSH 0x6aabc8)
0046240b: PUSH 0x6ab42c  ; "POWER ALL PACKAGE" (log)
; --- mode!=1 ---
00462421: TEST EAX,EAX
00462423: JNZ 0x00462464                      ; mode other than 0/1: no rewrite
00462425: PUSH 0x690f60                       ; ""
0046242a: PUSH dword ptr [EBP + -0x14]        ; Version
0046242d: CALL 0x00643b94
00462439: TEST EAX,EAX
0046243b: JZ 0x00462455                       ; Version=="" -> rewrite
0046243d: PUSH 0x6aabc8                       ; "v1"
00462442..462453: stricmp(Version,"v1"); JNZ 0x00462464
00462455: PUSH 0x2
00462457: PUSH 0x6aabe4                       ; "v2"
0046245c: LEA ECX,[EBP + -0x14]
0046245f: CALL 0x00409b20                     ; Version = "v2"
```
(String values verified by extracting from the PE: 0x690f60=`""`, 0x6aabc8=`"v1"`, 0x6aabe4=`"v2"`, 0x6aac00=`"v3"`, 0x6a5b60=`"h616"`, 0x6ab504=`"bound"`, 0x6ab50c=`"unbound"`, 0x6ab514=`"none"`, 0x6ab51c=`"btrom"`.)

### D. h616 branch and the static maps

```
0046249a: PUSH 0x6a5b60                ; "h616"
0046249f: PUSH dword ptr [EBP + -0x1c] ; Platform
004624a2: CALL 0x00643b94              ; stricmp
004624b3: JNZ 0x00462850               ; non-h616 generic concat path
004624b9..4624cd: if Bound=="bound"      -> use map 0x732a2c with key=Version
00462559..462587: if Bound=="unbound"/"none" -> use map 0x732a34 (0x4626f4)
0046258d..4625a1: if Bound!=""           -> bail (JNZ 0x462790, EBX=-1)
004625a7: PUSH 0x6ab51c                ; "btrom"
004625c0: MOV EDX,0x732a2c             ; btrom map
004625c6: MOV ECX,0x732a34             ; plain map
004625cb: CMOVZ ECX,EDX                ; Btrom=="btrom" ? btrom : plain
004625ce: CALL 0x00434910              ; map[Version]  (lookup-or-insert)
004625ee..4626b9: fallback key "v1" built and looked up in the same map -> [EBP-0x24]
00462790..4627af: FUN_0045e970 = find Target in ctx+0x14 (bundle section map)
004627b5..4627e3: if not found: retry [EBP-0x24] (the "v1" key) ONLY IF
                  param_3 (original PlatformVersion) == "" or "v1"
004627e5: PUSH 0x6ab570 ; "TargetChipTypePlatform: %s, not found in CombinedUpgradePlatform"
0046282d: PUSH 0x6ab528 ; "TargetChipTypePlatform: %s, not found in CombinedUpgradePlatform V1"
```

Static init (called from CRT static-init table, xrefs from 0x68e9d0/0x68ea00 regions):
- `FUN_00402000` → map **0x732a2c** = { `"v1"`→`"1011200000-h616-btrom"` @0x6aabb0, `"v2"`→`"1011200000-h616v2-btrom"` @0x6aabcc, `"v3"`→`"1011200000-h616v3-btrom"` @0x6aabe8 } (insert loop at 0x40223f, key pushes at 0x402079/0x40212b/0x4021cf).
- `FUN_00402290` → map **0x732a34** = { `"v1"`→`"0-h616"` @0x6aac04, `"v2"`→`"0-h616v2"` @0x6aac0c, `"v3"`→`"0-h616v3"` @0x6aac18 } (pushes at 0x402309/0x4023bb/0x40245f, ECX=0x732a34 at 0x4024ca).
- `FUN_00434910` is std::map::operator[] (lookup-or-insert), not string concat (disasm at 0x434910: tree descent + node alloc via FUN_004b3c32(0x18)).

### E. Where the suffix comes from — VERSUF (FUN_0049c2f0), input = firmware NAME

```
0049c36b: PUSH 0x2e ; '.'  0049c36d: PUSH 0x2  -> token #2 of name split by '.'
0049c3a0: PUSH 0x6aac00 ; cmp token,"v3"   -> JZ 0x0049c5a2 (return "v3")
0049c3b8: PUSH 0x6b5558 ; cmp "rel3"       -> JZ 0x0049c5a2 (return "v3")
0049c3d0: PUSH 0x6aabe4 ; cmp "v2"         -> JZ 0x0049c500 (return "v2")
0049c3e8: PUSH 0x6b5560 ; cmp "rel2"       -> JZ 0x0049c500 (return "v2")
0049c40a: PUSH 0x6b5568 ; _mbsstr(name,"NeedUpgradeAgain2") -> found -> return "v2"
0049c42d: PUSH 0x6b557c ; _mbsstr(name,"NeedUpgradeAgain1") -> found -> return "v2"
0049c4e9: MOV EAX,0x690f60  ; otherwise return ""
```
("v3" return path: 0x49c5c6 `MOV EAX,0x6aac00`; "v2": 0x49c46e / 0x49c524 `MOV EAX,0x6aabe4`.)

ChipTypePlatform builder `FUN_0049a3c0(dlg, out, fwrecord, flag)`: works off the firmware list/file entry — substring "M2"→chip "1920"@0x6b554c, "M3"→"1930"@0x6b5604, exact "1921/1922/1917/1918"→"1920"; if a record field == "1" it prepends "all-"@0x6b5590 and appends "-btrom"; else joins fields with '-'. Nothing from the miner identity.

### F. Where the bundle keys come from — READCOMB (FUN_004a7290)

Parses the combined file (magic 0xAE640A3F, CRC32, ≤0x40 sections). Per section builds the map key:
- `pi_version == 2` → `"<pi_chiptype>-<pi_platform>v2"[-btrom]`
- `pi_version == 3` → `"<pi_chiptype>-<pi_platform>v3"[-btrom]` (fmt `"%s-%sv3"` / `"%s-%sv3-btrom"`)
- otherwise → `"<pi_chiptype>-<pi_platform>"` (`"%s-%s"`)
- `-btrom` iff pi_chiptype=="1011200000" or ih_chiptype==0x3c45b000.
Writes only `ctx+0xc`=file buffer, `ctx+0x10`=section count; inserts into the ctx maps via FUN_004a5eb0. DECIDE's ctx+0x14 find (0x4627a3) matches the *requested* key against these bundle keys.

### G. The mode field (ctx+8) has no writer

- CTX ctor `FUN_0048e1f0` initializes `+0` (empty CString) and maps at `+0x14..+0x48` only (decomp + disasm verified — no `+4/+8/+0xc/+0x10` stores besides map nodes).
- `FUN_00478b30` zeroes `[EBP-0x80]`=ctx+0xc and `[EBP-0x7c]`=ctx+0x10 (0x478ba2/0x478ba9) but never `[EBP-0x84]`=ctx+8 (full function dump 0x478b30–0x479160 checked).
- CTX reset `FUN_004a79c0` (called first by FUN_004a7290) clears +0xc/+0x10 and the maps only.
- FUN_004a7290 itself writes only +0xc/+0x10.
- Embedded ctxs: `FUN_004a2920` zeroes 0x33d0/0x3420 (+0xc) and 0x33d4/0x3424 (+0x10) only (0x4a39ee–0x4a3a16); `FUN_004a67e0`/`FUN_004a6980` write only ctx+4 (the "combined?" flag) and hand the ctx to FUN_004a7290.
- Whole-binary immediate scan: **zero references** to 0x341c/0x33cc (ctx+8 of both embedded contexts). No REP STOS/memset in the dlg ctor FUN_0048e3b0 or in FUN_00478b30.
- Consequences: the field is dead legacy. Embedded ctxs sit on fresh (zero) memory, so mode==0 in practice → the ""→"v2" rewrite fires → `0-h616v2`. Even in the worst case (stack garbage in FUN_00478b30's local ctx): mode==1 would flip "v2"→"v1" (POWER ALL PACKAGE, target `0-h616`), and any other non-zero value leaves Version="" → fallback to `0-h616`. **No mode value can produce `0-h616v3`.**

### H. ctx+0x2970 family switch — refuted as suffix source

23 writers, all inside `FUN_00492aa0` (values 0..0x18 selected by other ctx fields / virtual-call results, GBK UI strings), e.g.
```
00492d9b: MOV [EDI+0x2970],0x0   ... 00494368: MOV [EDI+0x2970],0x18   (all in FUN_00492aa0)
```
Only reader: op dispatcher `FUN_004abd10` (0x4abe3d `MOV EAX,[EBX+0x2970]`, 0x4ace2e). No data-flow into FUN_00462240 / FUN_0049c2f0 / FUN_004a7290 / maps 0x732a2c/0x732a34.

### I. Board/chip strings are dead

- `H616-CB6V12` @0x006b21d8: **0 xrefs** (neighbors: "V12" @0x6b21e0, " (000)" @0x6b21f0, "firmware (000)" @0x6b2200 — UI list-format leftovers).
- `M64`, `CB6V5`, `H3VV08`: absent from the binary entirely.
- `L40`: no selection-path compares.

## Bottom line

`FUN_00462240` picks the sub-image by: Platform="h616" (from the *firmware record*, via FUN_0049a3c0) + Version suffix (from the *firmware file name*, via FUN_0049c2f0) + Bound/Btrom (caller-fixed "" / record-driven). Identity blob fields (incl. a hypothetical PlatformVersion) are never read in this path. With a name lacking a v3/rel3 token, mode==0 rewrites ""→"v2", map 0x732a34 gives **`0-h616v2`**, fallback `0-h616`; `0-h616v3` is unreachable without the filename saying so.
