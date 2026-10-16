# client/ — clean-room WhatsMiner 8889 upgrade client

Pure stdlib Python 3 (no dependencies). Implements `../docs/04` and `../docs/05`.

## Modules

- `aes256.py` — pure-Python AES-256-ECB (FIPS-197 KAT self-test: `python3 aes256.py`)
- `proto.py` — packet build/parse, session, crypto, upload stream, status poll
  (`python3 proto.py` runs self-tests)
- `bundle.py` — `whatsminer-all-*.bin` parser + sub-image selector (docs 01–03)
- `wmtcli.py` — CLI

## Use

```sh
cd client
python3 wmtcli.py --host <miner-ip> hello       # read-only: hello handshake (proto version)
python3 wmtcli.py --host <miner-ip> identity    # read-only: identity + selection inputs
python3 wmtcli.py --host <miner-ip> plan --bundle <whatsminer-all-*.bin>   # dry selection
python3 wmtcli.py --host <miner-ip> poll        # read-only: upgrade status
python3 wmtcli.py --host <miner-ip> upgrade --bundle <bin> --yes           # STATE-CHANGING
```

`upgrade` without `--yes` refuses before touching the network.
`--preset` additionally sends the `0x0D "3=1"` pre-flag (docs/05 step 5;
default off, matching a plain GUI upgrade click).

Safety: first live 8889 packet to a new miner should be `hello`/`identity`,
watched on the miner side if possible. No authentication is performed
(modern path sends none; see docs/06).
