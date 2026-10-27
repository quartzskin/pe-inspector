"""PE parsing. Files are only read as bytes, never loaded or run."""

from __future__ import annotations

import hashlib
import heapq
import itertools
import math
import re
from collections import Counter
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path

import pefile

MAX_FILE_SIZE = 256 * 1024 * 1024
MIN_PE_SIZE = 0x40 + 4 + 20
MAX_STRINGS = 5000
MIN_STRING_LEN = 5
HIGH_ENTROPY = 7.2
ELEVATED_ENTROPY = 6.5


class PEInspectError(Exception):
    """Input can't be analysed; the message is fine to show the user."""


@dataclass
class Section:
    name: str
    virtual_address: int
    virtual_size: int
    raw_offset: int
    raw_size: int
    entropy: float | None
    entropy_level: str
    permissions: str
    sha256: str
    warnings: list[str] = field(default_factory=list)


@dataclass
class ImportedFunction:
    name: str | None
    ordinal: int | None


@dataclass
class ImportedDll:
    dll: str
    functions: list[ImportedFunction]


@dataclass
class ExportedSymbol:
    name: str | None
    ordinal: int
    rva: int
    forwarder: str | None


@dataclass
class ExtractedString:
    offset: int
    encoding: str
    value: str


@dataclass
class PEReport:
    path: str
    file_name: str
    file_size: int
    md5: str
    sha1: str
    sha256: str
    machine: str
    pe_type: str
    kind: str
    subsystem: str
    timestamp: str | None
    image_base: int
    entry_point_rva: int
    entry_point_section: str | None
    entry_point_offset: int | None
    checksum_declared: int
    checksum_computed: int | None
    overlay_size: int
    imphash: str | None
    sections: list[Section]
    imports: list[ImportedDll]
    exports: list[ExportedSymbol]
    export_dll_name: str | None
    strings: list[ExtractedString]
    strings_truncated: bool
    warnings: list[str]

    def to_dict(self) -> dict:
        return asdict(self)


def shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    n = len(data)
    return -sum(c / n * math.log2(c / n) for c in Counter(data).values())


def entropy_level(entropy: float | None) -> str:
    if entropy is None:
        return "n/a"
    if entropy >= HIGH_ENTROPY:
        return "high"
    if entropy >= ELEVATED_ENTROPY:
        return "elevated"
    return "normal"


_ASCII_RE = re.compile(rb"[\x20-\x7e]{%d,}" % MIN_STRING_LEN)
_UTF16_RE = re.compile(rb"(?:[\x20-\x7e]\x00){%d,}" % MIN_STRING_LEN)


def extract_strings(data: bytes, limit: int = MAX_STRINGS) -> tuple[list[ExtractedString], bool]:
    """Strings in offset order. The flag is True if there were more than `limit`."""
    ascii_hits = (
        ExtractedString(m.start(), "ascii", m.group().decode("ascii")) for m in _ASCII_RE.finditer(data)
    )
    wide_hits = (
        ExtractedString(m.start(), "utf-16le", m.group().decode("utf-16le")) for m in _UTF16_RE.finditer(data)
    )
    merged = heapq.merge(ascii_hits, wide_hits, key=lambda s: s.offset)
    # one extra item tells us whether the cap cut anything off
    found = list(itertools.islice(merged, limit + 1))
    return found[:limit], len(found) > limit


def _permissions(characteristics: int) -> str:
    return "".join(
        c if characteristics & bit else "-"
        for c, bit in (("R", 0x40000000), ("W", 0x80000000), ("X", 0x20000000))
    )


def _text(raw: bytes | None) -> str:
    return (raw or b"").decode("ascii", "replace").rstrip("\x00")


def _timestamp(value: int) -> str | None:
    try:
        return datetime.fromtimestamp(value, timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    except (OverflowError, OSError, ValueError):
        return None


def read_pe_bytes(path: str | Path) -> bytes:
    p = Path(path)
    try:
        if not p.is_file():
            raise PEInspectError(f"Not a file: {p}")
        size = p.stat().st_size
        if size == 0:
            raise PEInspectError("File is empty.")
        if size > MAX_FILE_SIZE:
            raise PEInspectError(f"File is too large ({size:,} bytes; limit {MAX_FILE_SIZE:,}).")
        return p.read_bytes()
    except OSError as exc:
        raise PEInspectError(f"Cannot read file: {exc.strerror or exc}") from exc


def analyze_bytes(data: bytes, path: str = "<memory>") -> PEReport:
    if not data:
        raise PEInspectError("File is empty.")
    if len(data) < MIN_PE_SIZE or data[:2] != b"MZ":
        raise PEInspectError("Not a PE file: missing 'MZ' DOS header.")

    try:
        pe = pefile.PE(data=data, fast_load=True)
    except pefile.PEFormatError as exc:
        raise PEInspectError(f"Not a valid PE file: {exc}") from exc
    except Exception as exc:  # pefile raises all sorts on junk input
        raise PEInspectError(f"Failed to parse PE file: {type(exc).__name__}: {exc}") from exc

    try:
        return _build_report(pe, data, path)
    except PEInspectError:
        raise
    except Exception as exc:
        raise PEInspectError(f"Failed to analyse PE file: {type(exc).__name__}: {exc}") from exc
    finally:
        pe.close()


def analyze_file(path: str | Path) -> PEReport:
    return analyze_bytes(read_pe_bytes(path), str(path))


def _build_report(pe: pefile.PE, data: bytes, path: str) -> PEReport:
    warnings: list[str] = []
    fh = pe.FILE_HEADER
    oh = pe.OPTIONAL_HEADER
    if not fh.NumberOfSections:
        warnings.append("File declares no sections.")
    elif not pe.sections:
        raise PEInspectError("PE headers are truncated: the section table is missing.")

    pe.parse_data_directories(
        directories=[
            pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"],
            pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_EXPORT"],
        ]
    )

    sections: list[Section] = []
    for s in pe.sections:
        sec_warnings: list[str] = []
        start, size = s.PointerToRawData, s.SizeOfRawData
        raw = data[start : start + size]
        if len(raw) < size:
            sec_warnings.append("Raw data extends past end of file (truncated).")
        perms = _permissions(s.Characteristics)
        if "W" in perms and "X" in perms:
            sec_warnings.append("Writable and executable.")
        ent = shannon_entropy(raw) if raw else None
        sections.append(
            Section(
                name=_text(s.Name),
                virtual_address=s.VirtualAddress,
                virtual_size=s.Misc_VirtualSize,
                raw_offset=start,
                raw_size=size,
                entropy=round(ent, 4) if ent is not None else None,
                entropy_level=entropy_level(ent),
                permissions=perms,
                sha256=hashlib.sha256(raw).hexdigest(),
                warnings=sec_warnings,
            )
        )
    for sec in sections:
        if sec.warnings and "truncated" in sec.warnings[0]:
            warnings.append(f"Section {sec.name!r} is truncated.")

    ep = oh.AddressOfEntryPoint
    ep_section = ep_offset = None
    if ep:
        sec = pe.get_section_by_rva(ep)
        if sec is not None:
            ep_section = _text(sec.Name)
            ep_offset = pe.get_offset_from_rva(ep)
        else:
            warnings.append("Entry point lies outside every section.")

    imports: list[ImportedDll] = []
    for entry in getattr(pe, "DIRECTORY_ENTRY_IMPORT", []):
        funcs = [
            ImportedFunction(_text(i.name) if i.name else None, i.ordinal if not i.name else None)
            for i in entry.imports
        ]
        imports.append(ImportedDll(_text(entry.dll), funcs))

    exports: list[ExportedSymbol] = []
    export_dll = None
    exp = getattr(pe, "DIRECTORY_ENTRY_EXPORT", None)
    if exp is not None:
        export_dll = _text(exp.name) or None
        for sym in exp.symbols:
            exports.append(
                ExportedSymbol(
                    _text(sym.name) if sym.name else None,
                    sym.ordinal,
                    sym.address,
                    _text(sym.forwarder) if sym.forwarder else None,
                )
            )

    try:
        imphash = pe.get_imphash() or None
    except Exception:
        imphash = None
    try:
        computed = pe.generate_checksum()
    except Exception:
        computed = None
    if oh.CheckSum and computed is not None and oh.CheckSum != computed:
        warnings.append("Declared checksum does not match computed checksum.")

    overlay_at = pe.get_overlay_data_start_offset()
    overlay = max(0, len(data) - overlay_at) if overlay_at else 0
    warnings.extend(w.strip() for w in pe.get_warnings())

    strings, capped = extract_strings(data)
    is_dll = bool(fh.Characteristics & 0x2000)
    return PEReport(
        path=path,
        file_name=Path(path).name,
        file_size=len(data),
        md5=hashlib.md5(data, usedforsecurity=False).hexdigest(),
        sha1=hashlib.sha1(data, usedforsecurity=False).hexdigest(),
        sha256=hashlib.sha256(data).hexdigest(),
        machine=pefile.MACHINE_TYPE.get(fh.Machine, f"0x{fh.Machine:04x}"),
        pe_type="PE32+" if oh.Magic == 0x20B else "PE32",
        kind="DLL" if is_dll else "EXE",
        subsystem=pefile.SUBSYSTEM_TYPE.get(oh.Subsystem, f"0x{oh.Subsystem:04x}"),
        timestamp=_timestamp(fh.TimeDateStamp),
        image_base=oh.ImageBase,
        entry_point_rva=ep,
        entry_point_section=ep_section,
        entry_point_offset=ep_offset,
        checksum_declared=oh.CheckSum,
        checksum_computed=computed,
        overlay_size=overlay,
        imphash=imphash,
        sections=sections,
        imports=imports,
        exports=exports,
        export_dll_name=export_dll,
        strings=strings,
        strings_truncated=capped,
        warnings=warnings,
    )
