#!/usr/bin/env python3
"""wmtcli.py — clean-room WhatsMiner 8889 upgrade client CLI.

Usage:
  python3 wmtcli.py hello    --host 10.0.0.104
  python3 wmtcli.py identity --host 10.0.0.104
  python3 wmtcli.py plan     --host 10.0.0.104 --bundle whatsminer-all-....bin
  python3 wmtcli.py upgrade  --host 10.0.0.104 --bundle whatsminer-all-....bin [--preset] [--no-poll]
  python3 wmtcli.py poll     --host 10.0.0.104

Read-only commands: hello, identity, plan, poll.
State-changing command: upgrade (streams firmware, then polls unless --no-poll).
Beware vendor constraint: no rollback once on 20260908.12.
"""
import argparse, sys, time

from proto import Miner, ProtoError
from bundle import Bundle, BundleError

def _identity_to_selection(ident):
    """Map parsed identity -> (chiptype, platform, version, is_btrom).

    fw 20250409 (proto 16) sends NO ordered fields/PlatformVersion;
    everything comes from `Key = Value` lines. Mirrors the tool's rule
    (docs/03): version defaults to "v2" when absent; chiptype is "0"
    unless the miner reports btrom silicon (chiptype 1011200000)."""
    kv = ident["kv"]
    is_btrom = (kv.get("is_btrom") or "0").strip() in ("1", "true", "yes")
    chip = "1011200000" if is_btrom else "0"
    plat = (kv.get("ControlBoardType") or "h616").strip().lower()
    ver = (kv.get("PlatformVersion") or "v2").strip().lower()
    if not ver.startswith("v"):
        ver = "v2"
    return chip, plat, ver, is_btrom

def cmd_hello(m, a):
    s = m._connect()
    try:
        m.hello(s)
    finally:
        s.close()
    print("proto version:", m.proto_ver)

# Factory-default and common-stock candidates. hello-only, read-only.
PROBE_CREDS = [
    ("super", "super"),     # WhatsMinerTool factory default (ini-verified)
    ("root", "root"),
    ("admin", "admin"),
    ("admin", "F-0jk;"),    # second default pair literal found in app init
    ("super", "admin"),
]

def cmd_probe(m, a):
    """Try credential candidates against cmd 0 only; stop on first non-auth result."""
    for i, (u, p) in enumerate(PROBE_CREDS):
        if i:
            time.sleep(a.delay)
        mm = Miner(m.host, m.port, m.timeout, verbose=m.verbose, user=u, passwd=p)
        s = None
        try:
            s = mm._connect()
            mm.hello(s)
            print("probe %d: user=%r pass=%r -> OK, proto=%d flags=%#x"
                  % (i, u, p, mm.proto_ver, mm.session_flags))
            return 0
        except ProtoError as e:
            print("probe %d: user=%r pass=%r -> %s" % (i, u, p, e))
            if e.code not in (2, 5, 9):
                print("stopping: unexpected non-auth result")
                return 1
        except OSError as e:
            print("probe %d: connection error: %s" % (i, e))
            return 1
        finally:
            if s:
                try: s.close()
                except OSError: pass
    print("no candidate authenticated; supply real creds via WMT_USER/WMT_PASS")
    return 1

def cmd_identity(m, a):
    ident = m.identity()
    for i, x in enumerate(ident["fields"]):
        print("field[%d]: %r" % (i, x))
    for k in sorted(ident["kv"]):
        print("kv: %s = %s" % (k, ident["kv"][k]))
    sel = _identity_to_selection(ident)
    print("selection inputs: chiptype=%r platform=%r version=%r is_btrom=%s" % sel)

def _load_and_select(a, ident):
    b = Bundle(a.bundle)
    sel = _identity_to_selection(ident)
    entry = b.select(*sel)
    return b, entry, sel

def cmd_plan(m, a):
    ident = m.identity()
    b, entry, sel = _load_and_select(a, ident)
    print("selection key : %s" % entry.key)
    print("offset / size : %#x / %d bytes" % (entry.offset, entry.size))
    print("bundle ts     : %d" % b.build_ts)

def cmd_upgrade(m, a):
    ident = m.identity()
    print("identity fields:", ident["fields"])
    b, entry, sel = _load_and_select(a, ident)
    print("selected: %s (%d bytes)" % (entry.key, entry.size))
    if not a.yes:
        print("REFUSING without --yes (this stages firmware on the miner).")
        return 2
    image = b.image_bytes(entry)
    if a.preset:
        print("sending preset 0x0D '3=1' ...")
        m.preset_flag()
    m.prepare_and_stream(image)
    print("upload complete; miner is applying the image")
    if not a.no_poll:
        deadline = time.time() + a.poll_timeout
        while time.time() < deadline:
            time.sleep(a.poll_interval)
            try:
                st = m.poll_upgrade()
            except ProtoError as e:
                print("poll: %s" % e)
                continue
            print("poll: %s" % st)
            if st == "success":
                print("UPGRADE SUCCESS (miner will reboot itself)")
                return 0
            if st == "failed":
                print("UPGRADE FAILED")
                return 1
        print("poll timeout after %.0fs — check miner manually" % a.poll_timeout)
        return 3
    return 0

def cmd_poll(m, a):
    print("poll:", m.poll_upgrade())

def cmd_raw(m, a):
    SAFE = {0x00, 0x15, 0x16, 0x01}   # read-only cmdcodes only
    if a.code not in SAFE:
        print("refusing cmd %#x (allowlist: %s)" % (a.code, sorted(hex(x) for x in SAFE)))
        return 2
    rep = m.raw_cmd(a.code)
    print("result=%d payload=%r" % (rep["result"], rep["payload"][:96]))
    print("note: a genuine empty-payload error frame has crc=0xffffffff;"
          " anything else is a static responder")

def main():
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--host", required=True)
    p.add_argument("--port", type=int, default=8889)
    p.add_argument("--timeout", type=float, default=10.0)
    p.add_argument("--user", default=None, help="8889 account (env WMT_USER; default 'super')")
    p.add_argument("--passwd", default=None, help="8889 password (env WMT_PASS; default 'super')")
    p.add_argument("--quiet", action="store_true")
    sub = p.add_subparsers(dest="cmd", required=True)
    sub.add_parser("hello")
    pr = sub.add_parser("probe", help="hello with stock-cred candidates (read-only)")
    pr.add_argument("--delay", type=float, default=1.0)
    sub.add_parser("identity")
    rw = sub.add_parser("raw", help="debug: send an allowlisted read-only cmdcode, dump raw reply")
    rw.add_argument("--code", type=lambda s: int(s, 0), required=True)
    pl = sub.add_parser("plan"); pl.add_argument("--bundle", required=True)
    up = sub.add_parser("upgrade")
    up.add_argument("--bundle", required=True)
    up.add_argument("--yes", action="store_true", help="actually send firmware")
    up.add_argument("--preset", action="store_true", help="send 0x0D '3=1' first")
    up.add_argument("--no-poll", action="store_true")
    up.add_argument("--poll-interval", type=float, default=5.0)
    up.add_argument("--poll-timeout", type=float, default=1800.0)
    sub.add_parser("poll")
    a = p.parse_args()

    m = Miner(a.host, a.port, a.timeout, verbose=not a.quiet,
              user=a.user, passwd=a.passwd)
    fn = {"hello": cmd_hello, "probe": cmd_probe, "identity": cmd_identity,
          "plan": cmd_plan, "upgrade": cmd_upgrade, "poll": cmd_poll,
          "raw": cmd_raw}[a.cmd]
    try:
        return fn(m, a) or 0
    except (ProtoError, BundleError, OSError) as e:
        print("ERROR: %s" % e, file=sys.stderr)
        return 1

if __name__ == "__main__":
    sys.exit(main())
