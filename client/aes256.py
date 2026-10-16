#!/usr/bin/env python3
"""aes256.py — pure-stdlib AES-256 (ECB block) for wmt8889.

Reimplemented from the clean-room spec (wmt-re/docs/04 §4): standard
Rijndael with Nk=8, Nr=14. Equivalence with FIPS-197 was proven offline
against vector key=0001..1f pt=00112233..eeff ct=8ea2b7ca516745bfeafc49904b496089.
Only ECB block encrypt/decrypt are provided — the 8889 protocol encrypts
whole request packets and receives plaintext replies.
"""

SBOX = bytes([
0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16])

INVSBOX = [0]*256
for _i, _v in enumerate(SBOX):
    INVSBOX[_v] = _i
INVSBOX = bytes(INVSBOX)

def _xtime(x):
    return ((x << 1) ^ (0x1b if x & 0x80 else 0)) & 0xff

def _expand(key):
    if len(key) != 32:
        raise ValueError("AES-256 key must be 32 bytes")
    Nk, Nr = 8, 14
    w = [list(key[4*i:4*i+4]) for i in range(Nk)]
    rcon = 1
    for i in range(Nk, 4*(Nr+1)):
        t = list(w[i-1])
        if i % Nk == 0:
            t = [SBOX[b] for b in (t[1], t[2], t[3], t[0])]
            t[0] ^= rcon
            rcon = _xtime(rcon)
        elif i % Nk == 4:
            t = [SBOX[b] for b in t]
        w.append([w[i-Nk][j] ^ t[j] for j in range(4)])
    rk = bytearray()
    for i in range(4*(Nr+1)):
        rk += bytes(w[i])
    return bytes(rk)

_NR = 14

def _add_rk(st, rk, rnd):
    return [st[4*c+r] ^ rk[16*rnd + 4*c + r] for c in range(4) for r in range(4)]

def _shift(st):
    return [st[4*((c+r) % 4) + r] for c in range(4) for r in range(4)]

def _inv_shift(st):
    return [st[4*((c-r) % 4) + r] for c in range(4) for r in range(4)]

def _mix(st):
    out = [0]*16
    for c in range(4):
        a = st[4*c:4*c+4]
        out[4*c+0] = _xtime(a[0]) ^ (_xtime(a[1]) ^ a[1]) ^ a[2] ^ a[3]
        out[4*c+1] = a[0] ^ _xtime(a[1]) ^ (_xtime(a[2]) ^ a[2]) ^ a[3]
        out[4*c+2] = a[0] ^ a[1] ^ _xtime(a[2]) ^ (_xtime(a[3]) ^ a[3])
        out[4*c+3] = (_xtime(a[0]) ^ a[0]) ^ a[1] ^ a[2] ^ _xtime(a[3])
    return out

def _mul(x, y):
    r = 0
    while y:
        if y & 1: r ^= x
        x = _xtime(x)
        y >>= 1
    return r

def _inv_mix(st):
    out = [0]*16
    for c in range(4):
        a = st[4*c:4*c+4]
        out[4*c+0] = _mul(a[0],14) ^ _mul(a[1],11) ^ _mul(a[2],13) ^ _mul(a[3],9)
        out[4*c+1] = _mul(a[0],9)  ^ _mul(a[1],14) ^ _mul(a[2],11) ^ _mul(a[3],13)
        out[4*c+2] = _mul(a[0],13) ^ _mul(a[1],9)  ^ _mul(a[2],14) ^ _mul(a[3],11)
        out[4*c+3] = _mul(a[0],11) ^ _mul(a[1],13) ^ _mul(a[2],9)  ^ _mul(a[3],14)
    return out

class AES256ECB:
    def __init__(self, key):
        self._rk = _expand(key)

    def encrypt_block(self, pt):
        assert len(pt) == 16
        st = _add_rk(list(pt), self._rk, 0)
        for rnd in range(1, _NR):
            st = _add_rk(_mix(_shift([SBOX[b] for b in st])), self._rk, rnd)
        return bytes(_add_rk(_shift([SBOX[b] for b in st]), self._rk, _NR))

    def decrypt_block(self, ct):
        assert len(ct) == 16
        st = _add_rk(list(ct), self._rk, _NR)
        for rnd in range(_NR-1, 0, -1):
            st = [INVSBOX[b] for b in _inv_shift(st)]
            st = _inv_mix(_add_rk(st, self._rk, rnd))
        st = [INVSBOX[b] for b in _inv_shift(st)]
        return bytes(_add_rk(st, self._rk, 0))

    def encrypt(self, data):
        assert len(data) % 16 == 0
        return b"".join(self.encrypt_block(data[i:i+16]) for i in range(0, len(data), 16))

    def decrypt(self, data):
        assert len(data) % 16 == 0
        return b"".join(self.decrypt_block(data[i:i+16]) for i in range(0, len(data), 16))

def selftest():
    key = bytes(range(0x20))
    pt  = bytes.fromhex("00112233445566778899aabbccddeeff")
    want = bytes.fromhex("8ea2b7ca516745bfeafc49904b496089")
    a = AES256ECB(key)
    assert a.encrypt(pt) == want, "FIPS-197 AES-256 encrypt FAILED"
    assert a.decrypt(want) == pt, "FIPS-197 AES-256 decrypt FAILED"
    return True

if __name__ == "__main__":
    selftest()
    print("aes256 selftest OK")
