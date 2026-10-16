# wmt-re — Clean-room spec of MicroBT WhatsMinerTool firmware-upgrade path

Goal: document, from independent observation (static reverse engineering of
WhatsMinerTool 9.2.5 and the official firmware bundles), everything needed to
re-implement a Linux-native firmware-upgrade client for WhatsMiner miners
(target: M64/H616 via TCP 8889).

This is a **clean-room specification**: it describes *formats, protocols and
required behavior* — not MicroBT code. Provenance for every claim is recorded
per-document ("source: symbol X @ 0xADDR, disassembly/decompile" or "observed
on wire", etc.). Confidence labels: VERIFIED (matches two independent
observers or live behavior), DEDUCED (single-source static RE, high
confidence), UNVERIFIED (hypothesis pending live test).

## Docs

| # | File | Contents |
|---|------|----------|
| 00 | [docs/00-research-journal.md](docs/00-research-journal.md) | Full research narrative: failure ladder (result 2 → "result 16" → proto 16), dead ends, tooling lessons |
| 01 | [docs/01-firmware-bundle-format.md](docs/01-firmware-bundle-format.md) | `Whatsminer-all-*.bin` container: header, entry table, CRC, payload layout (VERIFIED) |
| 02 | [docs/02-subimage-format.md](docs/02-subimage-format.md) | `ih_magic` sub-image header (0xb8) + encrypted payload; streamed as-stored (no tool-side crypto needed) |
| 03 | [docs/03-image-selection.md](docs/03-image-selection.md) | Miner identity → selection key; key universe; identity reply = INI-ish key=value blob (live-verified) |
| 04 | [docs/04-protocol-8889.md](docs/04-protocol-8889.md) | TCP 8889: framing, payload-only CRC, AES-256-ECB keys, **auth envelope text = miner IP**, proto-in-hello-result, flags, cmdcodes, result codes |
| 05 | [docs/05-upgrade-flow.md](docs/05-upgrade-flow.md) | End-to-end upgrade choreography (modern flow), one-connection-per-command sequencing, abort semantics |
| 06 | [docs/06-gates-and-risks.md](docs/06-gates-and-risks.md) | Gates/refusals, proto-version floors, rollback ban, risk register |
| 07 | [docs/07-interrogating-your-miner.md](docs/07-interrogating-your-miner.md) | Shareable HOWTO: ports/daemons map, safe probes, auth model, result-code/debugging matrix, v3-first advice |
| 08 | [docs/08-undocumented-cmdcodes.md](docs/08-undocumented-cmdcodes.md) | Tool's full miner-facing command surface: op dispatcher, cmdcodes beyond doc 04 (accounts/pools/reboot/restore/upfreq…), cmd-0x0d key matrix, UDP 8888 listener, update server (VERIFIED-tool) |
| — | [docs/appendix/](docs/appendix/) | Durable evidence: audit reports (hello diff, result-code/proto mapping, image-selection), redacted live identity capture |

Status: **live-verified end-to-end** against the target M64 (fw 20250409.15.REL)
on 2026-10-15: hello (proto 16, session flags, K1→K2 switch), identity
(cmd 0x16), and `plan` sub-image selection (`0-h616v2`, 13,025,864 bytes)
all succeed with super/super on 8889; the official v3 `update_firmware`
init on 4433 also returns `ready` with super/super. Reference client in
[client/](client/README.md) (pure stdlib; KAT + selection self-tests green).
State-changing miner commands remain operator-executed by design (see
docs/06).

## Evidence base

- Tool under analysis: `WhatsMinerTool-customer.exe` 9.2.5 (x86 MFC),
  archive MD5 `a78c10923881f2166555baaac61700d9` (== S3 ETag), extracted exe
  MD5 `62609e0755e1eb46471c7a6446989f18`. Ghidra 11.0.3 project: `/tmp/ghproj`.
- Firmware: `whatsminer-all-20260908.12_1789959592535.bin`
  MD5 `93699b6c497fa9e378aa4e12b17606a0` (== S3 ETag), and
  `Whatsminer-all-20251209.16_1766476131037.bin` (older, comparison only).
- Target miner: 10.0.0.104, M64_VL40, CB6V5 (H616), fw 20250409.15.REL,
  API 3.0.1, PSU P738B.
- Live-test rules: any state-changing command to the miner is executed by the
  human operator only. Agent-run probes limited to read-only.
