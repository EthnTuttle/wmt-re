#!/usr/bin/env python3
"""bundle.py — parse `whatsminer-all-*.bin` and select a sub-image.

Implements wmt-re/docs/01, 02, 03. Read-only; selection is pure.
"""
import struct, zlib

MAGIC = 0xAE640A3F
HDR_CRC_OFF = 0x1A98
PAYLOAD_OFF = 0x1A9C
ENT_SIZE = 0x68
IH_MAGIC = 0x9A5BA57C
IH_CHIP_BTROM = 0x3C45B000      # 1011200000

class BundleError(Exception):
    pass

class Entry:
    def __init__(self, chiptype, platform, pi_version, offset, size):
        self.chiptype = chiptype
        self.platform = platform
        self.pi_version = pi_version
        self.offset = offset
        self.size = size
        self.key = "%s-%sv%d%s" % (
            chiptype or "0", platform, pi_version,
            "-btrom" if chiptype == "1011200000" else "")
        # V1 (version-less) key exists only for entries with an unknown/legacy
        # pi_version encoding (never observed in 2025+ bundles)
        self.key_v1 = None if pi_version in (2, 3) else "%s-%s%s" % (
            chiptype or "0", platform,
            "-btrom" if chiptype == "1011200000" else "")

    def __repr__(self):
        return "<Entry %s off=%#x size=%d>" % (self.key, self.offset, self.size)

class Bundle:
    def __init__(self, path):
        self.path = path
        with open(path, "rb") as f:
            self._hdr = f.read(PAYLOAD_OFF)
            f.seek(0, 2)
            self._size = f.tell()
        if len(self._hdr) < PAYLOAD_OFF:
            raise BundleError("file too small")
        magic, = struct.unpack_from("<I", self._hdr, 0)
        if magic != MAGIC:
            raise BundleError("bad magic %#010x" % magic)
        stored, = struct.unpack_from("<I", self._hdr, HDR_CRC_OFF)
        calc = zlib.crc32(self._hdr[:HDR_CRC_OFF]) ^ 0xFFFFFFFF
        if calc != stored:
            raise BundleError("header CRC mismatch: calc %#x stored %#x" % (calc, stored))
        self.build_ts, = struct.unpack_from("<I", self._hdr, 0x08)
        self.payload_size, = struct.unpack_from("<I", self._hdr, 0x10)
        n, = struct.unpack_from("<I", self._hdr, 0x14)
        if n > 0x41:
            raise BundleError("implausible entry count %d" % n)
        self.entries = []
        for i in range(n):
            o = 0x18 + i * ENT_SIZE
            chip = self._hdr[o:o+16].split(b"\0")[0].decode("ascii", "replace")
            plat = self._hdr[o+0x10:o+0x20].split(b"\0")[0].decode("ascii", "replace")
            off, size, piv = struct.unpack_from("<III", self._hdr, o+0x20)
            self._check_subimage(off, size)
            self.entries.append(Entry(chip, plat, piv, off, size))

    def _check_subimage(self, off, size):
        with open(self.path, "rb") as f:
            f.seek(off)
            h = f.read(0xB8)
        if len(h) < 0xB8:
            raise BundleError("truncated sub-image header")
        magic, tag, ver = struct.unpack_from("<III", h, 0)
        encsize, = struct.unpack_from("<I", h, 0x20)
        rsv, = struct.unpack_from("<I", h, 0x38)
        if magic != IH_MAGIC:
            raise BundleError("sub-image magic mismatch @%#x" % off)
        if tag not in (0x8C790AFE, 0x22FA87BD):
            raise BundleError("sub-image tag mismatch @%#x" % off)
        if 0xB8 + encsize != size:
            raise BundleError("sub-image size identity failed @%#x" % off)
        if rsv != 1:
            raise BundleError("sub-image reserved field unexpected @%#x" % off)

    def select(self, chiptype, platform, platform_version, is_btrom):
        """identity (from 8889 cmd 0x16) -> Entry. Mirrors docs/03."""
        chip = (chiptype or "0").strip() or "0"
        plat = (platform or "h6os").strip().lower()
        ver = (platform_version or "v2").strip().lower()
        key = "%s-%s%s%s" % (chip, plat, ver, "-btrom" if is_btrom else "")
        for e in self.entries:
            if e.key == key:
                return e
        # V1 alias: version-less key, matches only legacy untyped entries
        key_v1 = "%s-%s%s" % (chip, plat, "-btrom" if is_btrom else "")
        for e in self.entries:
            if e.key_v1 is not None and e.key_v1 == key_v1:
                return e
        raise BundleError(
            "TargetChipTypePlatform: %s, not found in CombinedUpgradePlatform V1 "
            "(have: %s)" % (key, ", ".join(e.key for e in self.entries)))

    def image_bytes(self, entry: Entry) -> bytes:
        with open(self.path, "rb") as f:
            f.seek(entry.offset)
            data = f.read(entry.size)
        if len(data) != entry.size:
            raise BundleError("short read")
        return data
