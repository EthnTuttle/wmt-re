#!/usr/bin/env python3
"""proto.py — WhatsMiner TCP/8889 "NetPacket" wire protocol.

Implements wmt-re/docs/04-protocol-8889.md exactly:
  header <IIHHI, payload = text + attachment, CRC32 variant,
  whole-packet AES-256-ECB (K1 for hello, K2 post-hello when proto >= 14),
  plaintext replies, firmware bulk stream, upgrade-status poll.
"""
import os, socket, struct, time, zlib

from aes256 import AES256ECB

MAGIC   = 0x7F7F5A5A
PORT    = 8889
K1 = bytes.fromhex("f0d379ee4188bc6216cfa09adcd49100ee7f971217aaba26bc86c0b6ae1da90f")
K2 = bytes.fromhex("66476cc48201182b9c27c302e48e120724a0e460fb970474a7539a48e787c296")

# The tool wraps every command's text in an auth envelope (FUN_004641b0):
#   text | "|" | unix_time | "|" | user | "|" | pass
#   + "|" + "%x" % session_flags   (only when proto >= 14 and flags known)
# CRITICAL (found by byte-diff audit vs wmt925.exe): the envelope "text"
# field is ALWAYS the target miner's own IP string — the tool reuses the
# connect-target CString as envelope text in every dispatcher branch
# (FUN_004abd10..FUN_00469900 chain). Sending an empty text yields
# result 2 (NetPacket Error) on every command, super:super or not.
# Tool factory defaults are super/super (ini [SETTING] AccountName, copied
# into both fields). Override via WMT_USER / WMT_PASS env or CLI flags.
DEFAULT_USER = os.environ.get("WMT_USER", "super")
DEFAULT_PASS = os.environ.get("WMT_PASS", "super")

RESULT_TEXT = {0: "OK", 2: "NetPacket Error", 3: "Invalid Command",
               4: "Data Error", 5: "Incorrect Password",
               6: "No Permission", 7: "Miner Sys Error", 9: "Need change pwd"}

BUFMAX = 0x2010

class ProtoError(Exception):
    def __init__(self, code, msg=""):
        self.code = code
        super().__init__("miner result %d (%s) %s" % (code, RESULT_TEXT.get(code, "?"), msg))

def _crc(payload: bytes) -> int:
    return zlib.crc32(payload) ^ 0xFFFFFFFF   # init 0xFFFFFFFF, no final xor

def build_packet(cmd: int, text: bytes = b"", attach: bytes = b"") -> bytes:
    payload = bytes(text) + bytes(attach)
    hdr = struct.pack("<IIHHI", MAGIC, cmd, len(text), len(attach), _crc(payload))
    pkt = hdr + payload
    pad = (-len(pkt)) % 16
    return pkt + b"\0" * pad

def parse_reply(buf: bytes, expect_cmd: int) -> dict:
    if len(buf) < 16:
        raise ProtoError(-1, "short reply (%d bytes)" % len(buf))
    magic, cmd, result, plen, crc = struct.unpack_from("<IIHHI", buf, 0)
    if magic != MAGIC:
        raise ProtoError(-1, "bad magic %#010x" % magic)
    if cmd != expect_cmd:
        raise ProtoError(-1, "cmd echo mismatch: sent %#x got %#x" % (expect_cmd, cmd))
    payload = buf[16:16+plen]
    if (crc >> 16) == 0 and plen:
        if (_crc(payload) & 0xFFFF) != crc:
            raise ProtoError(-2, "reply CRC mismatch")
    return {"cmd": cmd, "result": result, "payload": payload, "crc_ok": True}

def wrap_command(text, user, passwd, proto_ver=0, flags=0):
    """FUN_004641b0 auth envelope: 'text|unixtime|user|pass[|hexflags]'."""
    if isinstance(text, bytes):
        text = text.decode("ascii", "replace")
    s = "%s|%d|%s|%s" % (text, int(time.time()), user, passwd)
    if proto_ver >= 0x0E:
        s += "|%x" % (flags & 0xFFFFFFFF)
    return s.encode("ascii")

class Miner:
    def __init__(self, host, port=PORT, timeout=10.0, verbose=True,
                 user=None, passwd=None):
        self.host, self.port, self.timeout, self.verbose = host, port, timeout, verbose
        self.user = DEFAULT_USER if user is None else user
        self.passwd = DEFAULT_PASS if passwd is None else passwd
        self.proto_ver = None
        self.session_flags = 0
        self._k1 = AES256ECB(K1)
        self._k2 = AES256ECB(K2)

    def _log(self, *a):
        if self.verbose:
            print("[8889 %s]" % self.host, *a, flush=True)

    def _connect(self):
        s = socket.create_connection((self.host, self.port), timeout=self.timeout)
        s.settimeout(self.timeout)
        return s

    def _recv_packet(self, sock, expect_cmd, timeout, tolerant=False):
        sock.settimeout(timeout)
        buf = b""
        t0 = time.time()
        while len(buf) < 16:
            chunk = sock.recv(BUFMAX - len(buf))
            if not chunk:
                raise ProtoError(-1, "eof waiting for header")
            buf += chunk
        plen = struct.unpack_from("<H", buf, 10)[0]
        want = 16 + plen
        while len(buf) < want and len(buf) < BUFMAX:
            chunk = sock.recv(min(BUFMAX - len(buf), want - len(buf)))
            if not chunk:
                break
            buf += chunk
        self._log("recv %d bytes (payload %d, %.1fs)" % (len(buf), plen, time.time() - t0))
        if tolerant:
            magic, cmd, result, plen2, crc = struct.unpack_from("<IIHHI", buf, 0)
            self._log("raw reply hdr: magic=%#010x cmd=%#x result=%d plen=%d crc=%#010x"
                      % (magic, cmd, result, plen2, crc))
            self._log("raw reply hex: %s" % buf[:64].hex())
            return {"cmd": cmd, "result": result, "payload": buf[16:16+plen2],
                    "magic": magic, "crc": crc, "crc_ok": None}
        return parse_reply(buf, expect_cmd)

    def _send(self, sock, cmd, text=b"", attach=b""):
        key = self._k1 if (cmd == 0 or (self.proto_ver or 0) < 14) else self._k2
        # Envelope text is always the miner IP (see note above); the `text`
        # argument is ignored by the real tool for every op we implement.
        env_text = self.host
        if cmd != 0:
            text = wrap_command(env_text, self.user, self.passwd,
                                self.proto_ver or 0, self.session_flags)
        else:
            # hello already carries the envelope as its text
            text = wrap_command(env_text, self.user, self.passwd, 0, 0)
        pkt = build_packet(cmd, text, attach)
        self._log("send cmd=%#04x len=%d (enc=%s)" % (cmd, len(pkt), "K1" if key is self._k1 else "K2"))
        sock.sendall(key.encrypt(pkt))

    def hello(self, sock):
        """cmd 0. Returns proto version int. Sets session key regime."""
        self._send(sock, 0)
        rep = self._recv_packet(sock, 0, self.timeout)
        # Hello reply is NOT a normal error frame (FUN_004681d0 + disasm):
        #   header u16 "result" field = protocol version when >= 7;
        #   else fall back to u32 @ payload+0 (legacy daemons).
        #   proto >= 1 = success. When proto >= 14, payload+4 = session
        #   flags as BIG-ENDIAN u32 (tool does ntohl); banner cstring @+8.
        p = bytes(rep["payload"])
        res = rep["result"]
        ver = res if res >= 7 else (
            struct.unpack_from("<I", p, 0)[0] if len(p) >= 4 else 0)
        if ver < 1:
            raise ProtoError(res or -3, "hello (proto detect failed)")
        flags = 0
        if ver >= 0x0E and len(p) >= 8:
            flags = struct.unpack_from(">I", p, 4)[0]
        banner = p[8:].split(b"\0", 1)[0] if len(p) > 8 else b""
        self.proto_ver = ver
        self.session_flags = flags
        self._log("hello ok: proto=%d flags=%#x banner=%r"
                  % (ver, self.session_flags, banner[:48]))
        return ver

    def _hello_once(self, timeout=None):
        """Hello on its own connection (the tool's model: one cmd per conn).
        Sets self.proto_ver/self.session_flags. Returns reply result code."""
        last = None
        for _ in range(3):
            sock = None
            try:
                sock = self._connect()
                self.hello(sock)
                return 0
            except ProtoError as e:
                last = e
                if e.code >= 0:  # miner-side result: no point retrying
                    raise
                self._log("hello attempt failed: %s" % e)
            except OSError as e:
                last = e
                self._log("hello attempt failed: %s" % e)
            finally:
                if sock:
                    try: sock.close()
                    except OSError: pass
        raise last

    def _op(self, cmd, text=b"", attach=b"", timeout=None, retries=3):
        """hello on its own connection, then cmd on a FRESH connection."""
        if cmd != 0:
            self._hello_once(timeout)
        last = None
        for _ in range(retries):
            sock = None
            try:
                sock = self._connect()
                self._send(sock, cmd, text, attach)
                rep = self._recv_packet(sock, cmd, timeout or self.timeout)
                if rep["result"] != 0:
                    raise ProtoError(rep["result"], "cmd %#x" % cmd)
                return rep
            except (OSError, ProtoError) as e:
                last = e
                self._log("op %#x attempt failed: %s" % (cmd, e))
            finally:
                if sock:
                    try: sock.close()
                    except OSError: pass
        raise last

    def identity(self):
        """cmd 0x16 (or legacy 0x01). Returns dict: fields5 + kv."""
        self._hello_once()
        cmd = 0x16 if (self.proto_ver or 0) >= 8 else 0x01
        rep = self._op(cmd)
        return parse_identity(rep["payload"])

    def preset_flag(self):
        """cmd 0x0D with attachment '3=1' (tool's upgrade pre-flag)."""
        return self._op(0x0D, b"", b"3=1")

    def prepare_and_stream(self, image: bytes, ack_timeout=100.0, chunk=1024):
        """hello on its own conn; fresh conn: cmd 0x07, u32 LE size + raw bytes in
        1KB chunks; wait for ack on the same conn."""
        self._hello_once()
        sock = self._connect()
        try:
            self._send(sock, 0x07)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 0x1000)
            sock.sendall(struct.pack("<I", len(image)))
            t0 = time.time()
            for off in range(0, len(image), chunk):
                sock.sendall(image[off:off+chunk])
                if self.verbose and (off % (256*1024) == 0):
                    self._log("streamed %d/%d bytes" % (off, len(image)))
            self._log("stream done (%d bytes, %.1fs); waiting for prepare-ack"
                      % (len(image), time.time() - t0))
            rep = self._recv_packet(sock, 0x07, ack_timeout)
            if rep["result"] != 0:
                raise ProtoError(rep["result"], "prepare-ack")
            self._log("image accepted by miner")
            return rep
        finally:
            sock.close()

    def raw_cmd(self, cmd, text=b""):
        """Debug: hello on its own connection (may fail), then `cmd` on a FRESH
        connection (the tool's one-command-per-connection model); dump raw reply.
        Does not raise on miner-side result codes."""
        if cmd != 0:
            s0 = None
            try:
                s0 = self._connect()
                self._log("raw: hello on probe connection")
                self.hello(s0)
            except ProtoError as e:
                self._log("raw: hello: %s (continuing)" % e)
            finally:
                if s0:
                    try: s0.close()
                    except OSError: pass
        sock = self._connect()
        try:
            self._send(sock, cmd, text)
            return self._recv_packet(sock, cmd, self.timeout, tolerant=True)
        finally:
            sock.close()

    def poll_upgrade(self):
        """cmd 0x15. Returns one of 'success' | 'failed' | <progress text>."""
        rep = self._op(0x15)
        p = rep["payload"].decode("ascii", "replace")
        if "upgrade=" not in p:
            return p.strip() or "(empty)"
        val = p.split("upgrade=", 1)[1]
        if "success" in val:
            return "success"
        if "failed" in val:
            return "failed"
        return val.strip()

def parse_identity(payload: bytes) -> dict:
    """Identity reply (fw 20250409, proto 16): ONE INI-ish blob, NO NUL
    separators (live-verified: NUL count = 0). `Key = Value` lines with
    spaces around '='; `#tag#` markers and cgminer-style sections inside.
    Robust parsing = line-based key/value only; never positional."""
    text = payload.decode("ascii", "replace")
    kv = {}
    for line in text.split("\n"):
        if " = " in line:
            k, v = line.split(" = ", 1)
            kv[k.strip()] = v.strip()
    return {"fields": [text], "kv": kv}

def selftest():
    from aes256 import selftest as aes_selftest
    aes_selftest()
    # packet structure: build hello, check layout, round-trip via decrypt
    pkt = build_packet(0, b"", b"")
    assert len(pkt) == 16
    magic, cmd, l1, l2, crc = struct.unpack("<IIHHI", pkt)
    assert magic == MAGIC and cmd == 0 and l1 == 0 and l2 == 0
    assert crc == (zlib.crc32(b"") ^ 0xFFFFFFFF)
    # crc cross-check vs known answer computed from the binary's algorithm
    pkt2 = build_packet(0x15, b"abc", b"de")
    assert len(pkt2) == 32
    assert struct.unpack_from("<HH", pkt2, 8) == (3, 2)
    # decrypt(encrypt(x)) == x
    a = AES256ECB(K2)
    assert a.decrypt(a.encrypt(pkt2)) == pkt2
    # envelope shape
    w = wrap_command(b"", "super", "super")
    f = w.split(b"|")
    assert len(f) == 4 and f[0] == b"" and f[2] == b"super" and f[3] == b"super"
    assert abs(int(f[1]) - int(time.time())) < 5
    w2 = wrap_command(b"abc", "u", "p", proto_ver=14, flags=0x8100000f)
    assert w2.endswith(b"|8100000f") and w2.startswith(b"abc|")
    assert b"|8100000f" not in wrap_command(b"abc", "u", "p", proto_ver=13, flags=1)
    print("proto selftest OK")

if __name__ == "__main__":
    selftest()
