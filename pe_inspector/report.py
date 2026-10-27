from __future__ import annotations

import json
import re

from .analysis import PEReport

MD_STRING_LIMIT = 200

_SUMMARY_FIELDS = [
    ("File name", "file_name"),
    ("File size", "file_size"),
    ("MD5", "md5"),
    ("SHA-1", "sha1"),
    ("SHA-256", "sha256"),
    ("Machine", "machine"),
    ("Format", "pe_type"),
    ("Kind", "kind"),
    ("Subsystem", "subsystem"),
    ("Timestamp", "timestamp"),
    ("Image base", "image_base"),
    ("Entry point RVA", "entry_point_rva"),
    ("Entry point section", "entry_point_section"),
    ("Overlay size", "overlay_size"),
    ("Imphash", "imphash"),
]
_HEX_FIELDS = {"image_base", "entry_point_rva"}


def format_value(key: str, value: object) -> str:
    if value is None:
        return "-"
    if key in _HEX_FIELDS and isinstance(value, int):
        return f"0x{value:X}"
    if key in {"file_size", "overlay_size"} and isinstance(value, int):
        return f"{value:,}"
    return str(value)


def summary_rows(report: PEReport) -> list[tuple[str, str]]:
    return [(label, format_value(key, getattr(report, key))) for label, key in _SUMMARY_FIELDS]


def _import_set(report: PEReport) -> set[str]:
    out = set()
    for dll in report.imports:
        for fn in dll.functions:
            out.add(f"{dll.dll.lower()}!{fn.name if fn.name else f'#{fn.ordinal}'}")
    return out


def _export_set(report: PEReport) -> set[str]:
    return {e.name or f"#{e.ordinal}" for e in report.exports}


def compare_reports(a: PEReport, b: PEReport) -> dict:
    fields = []
    for label, key in _SUMMARY_FIELDS:
        va, vb = getattr(a, key), getattr(b, key)
        fields.append(
            {
                "field": label,
                "a": format_value(key, va),
                "b": format_value(key, vb),
                "differs": va != vb,
            }
        )

    secs_a = {s.name: s for s in a.sections}
    secs_b = {s.name: s for s in b.sections}
    sections = []
    for name in list(secs_a) + [n for n in secs_b if n not in secs_a]:
        sa, sb = secs_a.get(name), secs_b.get(name)
        if sa and sb:
            status = "identical" if sa.sha256 == sb.sha256 else "changed"
        else:
            status = "only in A" if sa else "only in B"
        sections.append(
            {
                "name": name,
                "status": status,
                "raw_size_a": sa.raw_size if sa else None,
                "raw_size_b": sb.raw_size if sb else None,
                "entropy_a": sa.entropy if sa else None,
                "entropy_b": sb.entropy if sb else None,
            }
        )

    ia, ib = _import_set(a), _import_set(b)
    ea, eb = _export_set(a), _export_set(b)
    sa_, sb_ = {s.value for s in a.strings}, {s.value for s in b.strings}
    return {
        "a": a.file_name,
        "b": b.file_name,
        "identical": a.sha256 == b.sha256,
        "fields": fields,
        "sections": sections,
        "imports_only_in_a": sorted(ia - ib),
        "imports_only_in_b": sorted(ib - ia),
        "exports_only_in_a": sorted(ea - eb),
        "exports_only_in_b": sorted(eb - ea),
        "strings_only_in_a": len(sa_ - sb_),
        "strings_only_in_b": len(sb_ - sa_),
        "strings_shared": len(sa_ & sb_),
    }


def to_json(report: PEReport, comparison: dict | None = None) -> str:
    payload: dict = {"report": report.to_dict()}
    if comparison is not None:
        payload["comparison"] = comparison
    return json.dumps(payload, indent=2)


_CONTROL = re.compile(r"[\x00-\x1f\x7f-\x9f\u2028\u2029]")
_MD_SPECIAL = re.compile(r"([\\`*_\[\]|~!#])")


def _cell(text: object) -> str:
    """Make untrusted text inert in Markdown: no HTML, links, emphasis or line breaks."""
    s = _CONTROL.sub(" ", str(text))
    s = s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    return _MD_SPECIAL.sub(r"\\\1", s)


def _table(headers: list[str], rows: list[list[object]]) -> list[str]:
    lines = ["| " + " | ".join(headers) + " |", "|" + "|".join("---" for _ in headers) + "|"]
    lines += ["| " + " | ".join(_cell(c) for c in row) + " |" for row in rows]
    return lines + [""]


def _fmt_entropy(value: float | None) -> str:
    return "-" if value is None else f"{value:.3f}"


def to_markdown(report: PEReport, comparison: dict | None = None) -> str:
    out = [f"# PE report: {_cell(report.file_name)}", ""]
    out += ["## Summary", ""]
    out += _table(["Field", "Value"], [list(r) for r in summary_rows(report)])

    if report.warnings:
        out += ["## Warnings", ""] + [f"- {_cell(w)}" for w in report.warnings] + [""]

    out += ["## Sections", ""]
    out += _table(
        ["Name", "VA", "VSize", "Raw size", "Perm", "Entropy", "Level", "Notes"],
        [
            [
                s.name,
                f"0x{s.virtual_address:X}",
                f"0x{s.virtual_size:X}",
                f"0x{s.raw_size:X}",
                s.permissions,
                _fmt_entropy(s.entropy),
                s.entropy_level,
                "; ".join(s.warnings),
            ]
            for s in report.sections
        ],
    )

    out += [f"## Imports ({sum(len(d.functions) for d in report.imports)})", ""]
    for dll in report.imports:
        names = ", ".join(f.name or f"#{f.ordinal}" for f in dll.functions)
        out.append(f"- **{_cell(dll.dll)}** ({len(dll.functions)}): {_cell(names)}")
    out.append("")

    title = f"## Exports ({len(report.exports)})"
    if report.export_dll_name:
        title += f" - {_cell(report.export_dll_name)}"
    out += [title, ""]
    out += _table(
        ["Ordinal", "Name", "RVA", "Forwarder"],
        [[e.ordinal, e.name or "-", f"0x{e.rva:X}", e.forwarder or ""] for e in report.exports],
    )

    shown = report.strings[:MD_STRING_LIMIT]
    note = f" (first {len(shown)} of {len(report.strings)})" if len(shown) < len(report.strings) else ""
    out += [f"## Strings{note}", ""]
    if report.strings_truncated:
        out += ["_String extraction hit its cap; more strings exist._", ""]
    out += _table(
        ["Offset", "Enc", "Value"],
        [[f"0x{s.offset:X}", s.encoding, s.value] for s in shown],
    )

    if comparison is not None:
        out += _comparison_markdown(comparison)
    return "\n".join(out).rstrip() + "\n"


def comparison_to_markdown(comparison: dict) -> str:
    return "\n".join(_comparison_markdown(comparison)).rstrip() + "\n"


def _comparison_markdown(c: dict) -> list[str]:
    out = [f"## Comparison: {_cell(c['a'])} vs {_cell(c['b'])}", ""]
    out += ["Files are byte-identical (same SHA-256).", ""] if c["identical"] else []
    out += _table(
        ["Field", "A", "B", "Differs"],
        [[f["field"], f["a"], f["b"], "yes" if f["differs"] else ""] for f in c["fields"]],
    )
    out += ["### Sections", ""]
    out += _table(
        ["Name", "Status", "Raw A", "Raw B", "Entropy A", "Entropy B"],
        [
            [
                s["name"],
                s["status"],
                "-" if s["raw_size_a"] is None else f"0x{s['raw_size_a']:X}",
                "-" if s["raw_size_b"] is None else f"0x{s['raw_size_b']:X}",
                _fmt_entropy(s["entropy_a"]),
                _fmt_entropy(s["entropy_b"]),
            ]
            for s in c["sections"]
        ],
    )
    for key, title in (
        ("imports_only_in_a", "Imports only in A"),
        ("imports_only_in_b", "Imports only in B"),
        ("exports_only_in_a", "Exports only in A"),
        ("exports_only_in_b", "Exports only in B"),
    ):
        out += [f"### {title} ({len(c[key])})", ""]
        out += [f"- {_cell(x)}" for x in c[key]] or ["_none_"]
        out.append("")
    out += [
        "### Strings",
        "",
        f"Shared: {c['strings_shared']}; only in A: {c['strings_only_in_a']}; "
        f"only in B: {c['strings_only_in_b']}",
        "",
    ]
    return out
