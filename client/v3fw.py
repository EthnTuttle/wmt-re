#!/usr/bin/env python3
"""v3fw.py — official v3 API firmware update for WhatsMiner (port 4433).

Flow per apidoc.whatsminer.com (set.system.update_firmware):
  1) JSON init  {"cmd":"set.system.update_firmware","token":..,"account":..,"ts":..}
  2) server -> {"code":0,"msg":"ready",...}   (we verify "ready")
  3) client sends u32 LE total_size then the raw firmware file bytes
  4) server replies final confirmation; device reboots to apply.

Token: base64(sha256(f"{cmd}{password}{salt}{ts}"))[:8]   (apidoc token section)
Framing: 4-byte LE length prefix + JSON, both directions.

Modes:
  probe   -- only the init step (no bytes sent; nothing staged). Answers
             "is this account allowed to update firmware?" read-only-ish.
  run     -- full upload of --file after explicit --yes.

Credentials: pass via env WM_FW_PASSWORD (never printed).
"""
from __future__ import annotations
import argparse, base64, hashlib, json, os, socket, struct, sys, time

HOST_DEFAULT = "10.0.0.104"
V3_PORT = 4433
MAX_FRAME = 1 << 20

def rpc_sock(s: socket.socket, payload: dict, timeout: float = 20) -> dict:
    s.settimeout(timeout)
    raw = json.dumps(payload).encode()
    s.sendall(struct.pack("<I", len(raw)) + raw)
    hdr = b""
    while len(hdr) < 4:
        chunk = s.recv(4 - len(hdr))
        if not chunk:
            raise ConnectionError("closed before response header")
        hdr += chunk
    (n,) = struct.unpack("<I", hdr)
    if n > MAX_FRAME:
        raise ValueError("implausible frame length %d" % n)
    body = b""
    while len(body) < n:
        chunk = s.recv(n - len(body))
        if not chunk:
            break
        body += chunk
    return json.loads(body)

def get_salt(host: str) -> str:
    with socket.create_connection((host, V3_PORT), timeout=15) as s:
        resp = rpc_sock(s, {"cmd": "get.device.info", "param": "salt"})
    if resp.get("code") != 0:
        raise RuntimeError("salt fetch: code=%r msg=%r" % (resp.get("code"), resp.get("msg")))
    salt = (resp.get("msg") or {}).get("salt")
    if not salt:
        raise RuntimeError("salt missing: %r" % (resp,))
    return salt

def make_token(cmd: str, password: str, salt: str, ts: int) -> str:
    return base64.b64encode(
        hashlib.sha256(f"{cmd}{password}{salt}{ts}".encode()).digest()
    ).decode()[:8]

def probe_init(host: str, account: str, password: str):
    """Send only the init request; return the reply dict. Never sends file data."""
    cmd = "set.system.update_firmware"
    salt = get_salt(host)
    ts = int(time.time())
    payload = {"cmd": cmd, "token": make_token(cmd, password, salt, ts),
               "account": account, "ts": ts}
    with socket.create_connection((host, V3_PORT), timeout=15) as s:
        return rpc_sock(s, payload)

def query_t(host: str):
    with socket.create_connection((host, V3_PORT), timeout=15) as s:
        return rpc_sock(s, {"cmd": "get.system.setting"})

def run_upload(host: str, account: str, password: str, path: str, poll_sec: float = 600):
    cmd = "set.system.update_firmware"
    salt = get_salt(host)
    ts = int(time.time())
    init = {"cmd": cmd, "token": make_token(cmd, password, salt, ts),
            "account": account, "ts": ts}
    data = open(path, "rb").read()
    print("file: %s (%d bytes)" % (path, len(data)))
    print("sha256:", hashlib.sha256(data).hexdigest())
    with socket.create_connection((host, V3_PORT), timeout=30) as s:
        resp = rpc_sock(s, init)
        print("init reply: code=%r msg=%r desc=%r" % (resp.get("code"), resp.get("msg"), resp.get("desc")))
        if not (resp.get("code") == 0 and str(resp.get("msg")).lower() == "ready"):
            print("server not ready; aborting before any transfer")
            return 1
        s.settimeout(120)
        s.sendall(struct.pack("<I", len(data)))
        t0 = time.time()
        s.sendall(data)
        print("sent %d bytes in %.1fs; waiting confirmation..." % (len(data), time.time() - t0))
        # the confirmation is another framed JSON on the same socket
        try:
            s.settimeout(300)
            hdr = b""
            while len(hdr) < 4:
                c = s.recv(4 - len(hdr))
                if not c:
                    raise ConnectionError("closed before final header")
                hdr += c
            (n,) = struct.unpack("<I", hdr)
            body = b""
            while len(body) < n:
                c = s.recv(n - len(body))
                if not c: break
                body += c
            print("final reply:", body[:300])
        except Exception as e:
            print("no final reply on that socket (%r); miner may have started applying" % e)
    if poll_sec:
        print("polling device info until fw changes / uptime resets (max %.0fs)..." % poll_sec)
        end = time.time() + poll_sec
        while time.time() < end:
            try:
                with socket.create_connection((host, 4028), timeout=10) as s2:
                    s2.sendall(b'{"cmd":"get_version"}')
                    ans = s2.recv(4096).decode("utf-8", "ignore")
                print("get_version:", ans[:200])
                if "20260908" in ans:
                    print("TARGET FIRMWARE CONFIRMED RUNNING")
                    return 0
            except Exception as e:
                print("poll: %r" % e)
            time.sleep(15)
    return 0

def v3_write(host: str, cmd: str, password: str, param=None):
    """One tokened v3 write (account super). Returns the reply dict."""
    salt = get_salt(host)
    ts = int(time.time())
    payload = {"cmd": cmd, "token": make_token(cmd, password, salt, ts),
               "account": "super", "ts": ts}
    if param is not None:
        payload["param"] = param
    with socket.create_connection((host, V3_PORT), timeout=15) as s:
        return rpc_sock(s, payload)


def watch_for_version(host: str, want: str, poll_sec: float = 900):
    """Poll v2 get_version until fw_ver contains `want` (or timeout)."""
    end = time.time() + poll_sec
    while time.time() < end:
        try:
            with socket.create_connection((host, 4028), timeout=10) as s2:
                s2.sendall(b'{"cmd":"get_version"}')
                ans = s2.recv(4096).decode("utf-8", "ignore")
            fw = ans if len(ans) < 400 else ans[:160]
            print("get_version:", fw.replace("\n", " "))
            if want in ans:
                print("TARGET FIRMWARE CONFIRMED RUNNING")
                return 0
        except Exception as e:
            print("poll: %r (miner busy/rebooting)" % e)
        time.sleep(15)
    print("poll window expired without seeing", want)
    return 1


def main():
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--host", default=HOST_DEFAULT)
    p.add_argument("--account", default="admin")
    sub = p.add_subparsers(dest="mode", required=True)
    sub.add_parser("probe", help="init only; nothing is staged")
    sub.add_parser("setting", help="read-only get.system.setting")
    rb = sub.add_parser("reboot", help="set.system.reboot (super), then watch for a target fw")
    rb.add_argument("--watch", default="20260908.12")
    rb.add_argument("--yes", action="store_true")
    w = sub.add_parser("watch", help="poll get_version until the target fw reports back")
    w.add_argument("--watch", default="20260908.12")
    w.add_argument("--poll", type=float, default=900)
    r = sub.add_parser("run", help="full upload (needs --yes)")
    r.add_argument("--file", required=True)
    r.add_argument("--yes", action="store_true")
    r.add_argument("--poll", type=float, default=600)
    a = p.parse_args()

    pw = os.environ.get("WM_FW_PASSWORD")
    if a.mode != "setting" and not pw:
        print("WM_FW_PASSWORD not set", file=sys.stderr)
        return 2

    if a.mode == "setting":
        print(json.dumps(query_t(a.host), indent=1)[:2000])
        return 0

    if a.mode == "probe":
        resp = probe_init(a.host, a.account, pw)
        print("probe reply: %s" % json.dumps(resp))
        return 0 if resp.get("code") == 0 else 1

    if a.mode == "reboot":
        if not a.yes:
            print("refusing without --yes (this reboots the miner)")
            return 2
        try:
            resp = v3_write(a.host, "set.system.reboot", pw)
        except Exception as e:
            print("reboot request transport error (%r); the miner may already be cycling" % e)
            resp = {"code": None}
        print("reboot reply:", json.dumps(resp))
        print("watching for firmware", a.watch, "…")
        return watch_for_version(a.host, a.watch)

    if a.mode == "watch":
        return watch_for_version(a.host, a.watch, a.poll)

    if a.mode == "run":
        if not a.yes:
            print("refusing without --yes (this uploads firmware and triggers upgrade)")
            return 2
        return run_upload(a.host, a.account, pw, a.file, a.poll)

if __name__ == "__main__":
    sys.exit(main())
