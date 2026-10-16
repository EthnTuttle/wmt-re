#!/usr/bin/env python3
"""identdump.py — read-only structural dump of the cmd 0x16 identity reply.

Shows NUL positions and segment boundaries so we can mirror the tool's
parser exactly. Prints NO serials/MACs/pool data: values are truncated and
long alnum runs masked.
"""
import re, sys
from proto import Miner

def mask(s: str) -> str:
    s = re.sub(r"[A-Za-z0-9]{6,}", lambda m: m.group(0)[:2] + "*" * (len(m.group(0)) - 4) + m.group(0)[-2:], s)
    return s

def main():
    host = sys.argv[1] if len(sys.argv) > 1 else "10.0.0.104"
    m = Miner(host)
    m._hello_once()
    # raw identity fetch on one fresh connection (one-cmd-per-conn model)
    cmd = 0x16 if (m.proto_ver or 0) >= 8 else 0x01
    s = m._connect()
    try:
        m._send(s, cmd)
        rep = m._recv_packet(s, cmd, m.timeout)
    finally:
        s.close()
    if rep["result"] != 0:
        print("identity result:", rep["result"]); return
    p = bytes(rep["payload"])
    print("payload length:", len(p))
    nuls = [i for i, b in enumerate(p) if b == 0]
    print("NUL count:", len(nuls), "at:", nuls[:20])
    parts = p.split(b"\0")
    for i, part in enumerate(parts[:8]):
        print("--- part[%d] len=%d starts: %r" % (i, len(part), mask(part[:100].decode("ascii", "replace"))))
    print("--- last 120 chars:", repr(mask(p[-120:].decode("ascii", "replace"))))
    # '#' separators
    idx = [m.start() for m in re.finditer(rb"#[^#\n]{1,40}#", p)]
    print("'#tag#' markers at:", idx[:20])
    for m in re.finditer(rb"#[^#\n]{1,40}#", p):
        print("   marker:", repr(mask(m.group(0).decode("ascii", "replace"))))

if __name__ == "__main__":
    main()
