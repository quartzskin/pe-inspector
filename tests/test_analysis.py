import json
import os
import random
from pathlib import Path

import pytest

from pe_inspector.analysis import (
    MAX_FILE_SIZE,
    PEInspectError,
    analyze_bytes,
    analyze_file,
    entropy_level,
    extract_strings,
    shannon_entropy,
)
from pe_inspector.synthetic import build_synthetic_pe


@pytest.fixture
def pe_bytes() -> bytes:
    return build_synthetic_pe()


@pytest.fixture
def pe_file(tmp_path: Path, pe_bytes: bytes) -> Path:
    p = tmp_path / "sample.exe"
    p.write_bytes(pe_bytes)
    return p


def test_metadata_and_hashes(pe_file: Path, pe_bytes: bytes):
    import hashlib

    r = analyze_file(pe_file)
    assert r.sha256 == hashlib.sha256(pe_bytes).hexdigest()
    assert r.file_size == len(pe_bytes)
    assert r.machine == "IMAGE_FILE_MACHINE_I386"
    assert r.pe_type == "PE32"
    assert r.kind == "EXE"
    assert r.entry_point_rva == 0x1000
    assert r.entry_point_section == ".text"
    assert r.entry_point_offset == 0x400
    assert r.timestamp == "2020-07-04 04:05:20 UTC"
    assert r.overlay_size == 0


def test_dll_flag():
    assert analyze_bytes(build_synthetic_pe(dll=True)).kind == "DLL"


def test_sections_and_entropy(pe_bytes: bytes):
    r = analyze_bytes(pe_bytes)
    by_name = {s.name: s for s in r.sections}
    assert list(by_name) == [".text", ".idata", ".edata", ".rand"]
    assert by_name[".text"].permissions == "R-X"
    assert by_name[".text"].entropy_level == "normal"
    assert by_name[".rand"].entropy > 7.2
    assert by_name[".rand"].entropy_level == "high"
    assert by_name[".rand"].raw_size == 0x400


def test_imports_and_exports(pe_bytes: bytes):
    r = analyze_bytes(pe_bytes)
    assert [d.dll for d in r.imports] == ["KERNEL32.dll"]
    assert [f.name for f in r.imports[0].functions] == ["ExitProcess", "GetTickCount"]
    assert r.export_dll_name == "synthetic.dll"
    assert [(e.name, e.ordinal, e.rva) for e in r.exports] == [("SyntheticExport", 1, 0x1000)]
    assert r.imphash


def test_strings_ascii_and_utf16(pe_bytes: bytes):
    values = {(s.encoding, s.value) for s in analyze_bytes(pe_bytes).strings}
    assert ("ascii", "Hello from a synthetic PE") in values
    assert ("utf-16le", "wide str") in values


def test_extract_strings_cap_and_min_length():
    strings, capped = extract_strings(b"abcd\x00abcde\x00fghij\x00klmno", limit=2)
    assert [s.value for s in strings] == ["abcde", "fghij"]
    assert capped


def test_entropy_helpers():
    assert shannon_entropy(b"") == 0.0
    assert shannon_entropy(b"\x00" * 100) == 0.0
    assert shannon_entropy(bytes(range(256))) == pytest.approx(8.0)
    assert entropy_level(None) == "n/a"
    assert entropy_level(6.6) == "elevated"
    assert entropy_level(7.5) == "high"


def test_json_serialisable(pe_bytes: bytes):
    from pe_inspector.report import to_json

    data = json.loads(to_json(analyze_bytes(pe_bytes)))
    assert data["report"]["sections"][3]["entropy_level"] == "high"


def test_truncated_section_data_warns(pe_bytes: bytes):
    r = analyze_bytes(pe_bytes[:-0x100])
    assert any("truncated" in w for w in r.warnings)
    assert r.sections[-1].warnings


# --- malformed input must fail safely ---------------------------------


def test_empty_file(tmp_path: Path):
    p = tmp_path / "empty.exe"
    p.write_bytes(b"")
    with pytest.raises(PEInspectError, match="empty"):
        analyze_file(p)


def test_missing_file(tmp_path: Path):
    with pytest.raises(PEInspectError, match="Not a file"):
        analyze_file(tmp_path / "nope.exe")


def test_directory(tmp_path: Path):
    with pytest.raises(PEInspectError):
        analyze_file(tmp_path)


def test_non_pe_text(tmp_path: Path):
    p = tmp_path / "a.exe"
    p.write_text("hello world, definitely not a PE file" * 10)
    with pytest.raises(PEInspectError, match="MZ"):
        analyze_file(p)


def test_mz_only():
    with pytest.raises(PEInspectError):
        analyze_bytes(b"MZ" + b"\x00" * 100)


def test_bad_pe_signature(pe_bytes: bytes):
    broken = bytearray(pe_bytes)
    broken[0x40:0x44] = b"XXXX"
    with pytest.raises(PEInspectError, match="Not a valid PE"):
        analyze_bytes(bytes(broken))


def test_lfanew_beyond_file(pe_bytes: bytes):
    broken = bytearray(pe_bytes)
    broken[0x3C:0x40] = (0x7FFFFFF0).to_bytes(4, "little")
    with pytest.raises(PEInspectError):
        analyze_bytes(bytes(broken))


@pytest.mark.parametrize("cut", [2, 0x40, 0x44, 0x60, 0x100])
def test_truncated_headers(pe_bytes: bytes, cut: int):
    with pytest.raises(PEInspectError):
        analyze_bytes(pe_bytes[:cut])


def test_truncated_after_headers_parses_with_warnings(pe_bytes: bytes):
    r = analyze_bytes(pe_bytes[:0x200])
    assert len(r.sections) == 4
    assert any("truncated" in w for w in r.warnings)


def test_garbage_after_valid_dos_header_never_crashes(pe_bytes: bytes):
    rng = random.Random(7)
    for _ in range(200):
        data = bytearray(pe_bytes)
        for _ in range(rng.randint(1, 20)):
            data[rng.randrange(0x400)] = rng.randrange(256)
        try:
            analyze_bytes(bytes(data))
        except PEInspectError:
            pass  # any other exception type fails the test


def test_oversized_file_rejected(tmp_path: Path, monkeypatch):
    p = tmp_path / "big.exe"
    p.write_bytes(b"MZ" + b"\x00" * 64)
    monkeypatch.setattr("pe_inspector.analysis.MAX_FILE_SIZE", 10)
    assert MAX_FILE_SIZE == 256 * 1024 * 1024
    with pytest.raises(PEInspectError, match="too large"):
        analyze_file(p)


@pytest.mark.skipif(
    not Path(os.environ.get("SystemRoot", "C:\\Windows"), "System32", "notepad.exe").exists(),
    reason="no Windows system binary available",
)
def test_real_system_binary_parses_read_only():
    path = Path(os.environ["SystemRoot"], "System32", "notepad.exe")
    before = path.stat().st_mtime_ns
    r = analyze_file(path)
    assert r.sections and r.imports and len(r.sha256) == 64
    assert path.stat().st_mtime_ns == before


def test_extract_strings_mixed_order_stops_at_cap():
    data = b"hello\x01" + "wide!".encode("utf-16le") + b"\x00world\x00more!"
    strings, capped = extract_strings(data, limit=3)
    assert [s.value for s in strings] == ["hello", "wide!", "world"]
    assert [s.encoding for s in strings] == ["ascii", "utf-16le", "ascii"]
    assert capped
    assert not extract_strings(data, limit=4)[1]
