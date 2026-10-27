"""Builds a tiny PE32 image for tests and screenshots. Not meant to run."""

from __future__ import annotations

import random
import struct

_SECTION_ALIGN = 0x1000
_FILE_ALIGN = 0x200
_TEXT_RVA, _IDATA_RVA, _EDATA_RVA, _RAND_RVA = 0x1000, 0x2000, 0x3000, 0x4000


def _pad(data: bytes, size: int) -> bytes:
    return data + b"\x00" * (size - len(data))


def _idata() -> bytes:
    base = _IDATA_RVA
    buf = bytearray(0x200)
    # descriptor: OriginalFirstThunk, TimeDateStamp, ForwarderChain, Name, FirstThunk
    struct.pack_into("<5I", buf, 0, base + 0x28, 0, 0, base + 0x48, base + 0x38)
    for off in (0x28, 0x38):
        struct.pack_into("<3I", buf, off, base + 0x60, base + 0x70, 0)
    buf[0x48:0x55] = b"KERNEL32.dll\x00"
    buf[0x60:0x6E] = struct.pack("<H", 0) + b"ExitProcess\x00"
    buf[0x70:0x7F] = struct.pack("<H", 0) + b"GetTickCount\x00"
    return bytes(buf)


def _edata() -> bytes:
    base = _EDATA_RVA
    buf = bytearray(0x200)
    struct.pack_into(
        "<IIHHIIIIIII", buf, 0, 0, 0, 0, 0, base + 0x50, 1, 1, 1, base + 0x28, base + 0x2C, base + 0x30
    )
    struct.pack_into("<I", buf, 0x28, _TEXT_RVA)
    struct.pack_into("<I", buf, 0x2C, base + 0x60)
    struct.pack_into("<H", buf, 0x30, 0)
    buf[0x50:0x5E] = b"synthetic.dll\x00"
    buf[0x60:0x70] = b"SyntheticExport\x00"
    return bytes(buf)


def build_synthetic_pe(*, dll: bool = False, text_string: bytes = b"Hello from a synthetic PE") -> bytes:
    text = _pad(b"\x31\xc0\xc3" + b"\x00" + text_string + b"\x00\x00" + "wide str".encode("utf-16le"), 0x200)
    rand = random.Random(1234).randbytes(0x400)  # deterministic, ~8 bits/byte
    # (name, rva, vsize, data, flags)
    sections = [
        (b".text", _TEXT_RVA, 0x200, text, 0x60000020),
        (b".idata", _IDATA_RVA, 0x200, _idata(), 0xC0000040),
        (b".edata", _EDATA_RVA, 0x200, _edata(), 0x40000040),
        (b".rand", _RAND_RVA, 0x400, rand, 0xC0000040),
    ]
    headers_size = 0x400
    dos = _pad(b"MZ", 0x3C) + struct.pack("<I", 0x40)
    characteristics = 0x0102 | (0x2000 if dll else 0)
    file_header = struct.pack("<HHIIIHH", 0x14C, len(sections), 0x5F000000, 0, 0, 224, characteristics)
    dirs = bytearray(16 * 8)
    struct.pack_into("<II", dirs, 0, _EDATA_RVA, 0x70)  # export
    struct.pack_into("<II", dirs, 8, _IDATA_RVA, 0x80)  # import
    optional = struct.pack(
        "<HBB9I6H4I2H6I",
        0x10B, 14, 0, 0x200, 0x800, 0, _TEXT_RVA, _TEXT_RVA, _IDATA_RVA, 0x10000000,
        _SECTION_ALIGN, _FILE_ALIGN, 6, 0, 0, 0, 6, 0,
        0, 0x5000, headers_size, 0, 3, 0,
        0x100000, 0x1000, 0x100000, 0x1000, 0, 16,
    ) + bytes(dirs)  # fmt: skip
    table = b""
    body = b""
    raw_ptr = headers_size
    for name, rva, vsize, data, flags in sections:
        table += struct.pack("<8sIIIIIIHHI", name, vsize, rva, len(data), raw_ptr, 0, 0, 0, 0, flags)
        body += data
        raw_ptr += len(data)
    header = dos + b"PE\x00\x00" + file_header + optional + table
    return _pad(header, headers_size) + body
