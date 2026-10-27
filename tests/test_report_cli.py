import json
from pathlib import Path

from pe_inspector.analysis import analyze_bytes
from pe_inspector.cli import main
from pe_inspector.report import compare_reports, to_json, to_markdown
from pe_inspector.synthetic import build_synthetic_pe


def test_compare_identical():
    a = analyze_bytes(build_synthetic_pe())
    c = compare_reports(a, analyze_bytes(build_synthetic_pe()))
    assert c["identical"]
    assert not any(f["differs"] for f in c["fields"] if f["field"] != "File name")
    assert {s["status"] for s in c["sections"]} == {"identical"}
    assert c["imports_only_in_a"] == c["imports_only_in_b"] == []


def test_compare_different():
    a = analyze_bytes(build_synthetic_pe())
    b = analyze_bytes(build_synthetic_pe(dll=True, text_string=b"A different string!"))
    c = compare_reports(a, b)
    assert not c["identical"]
    differing = {f["field"] for f in c["fields"] if f["differs"]}
    assert {"SHA-256", "Kind"} <= differing
    statuses = {s["name"]: s["status"] for s in c["sections"]}
    assert statuses[".text"] == "changed"
    assert statuses[".rand"] == "identical"
    assert c["strings_only_in_a"] == 1 and c["strings_only_in_b"] == 1


def test_markdown_contains_sections_and_escapes_pipes():
    r = analyze_bytes(build_synthetic_pe(text_string=b"pipe|inside"))
    md = to_markdown(r, compare_reports(r, r))
    assert "## Sections" in md and "| .rand |" in md
    assert "KERNEL32.dll" in md and "SyntheticExport" in md
    assert "pipe\\|inside" in md
    assert "## Comparison" in md


def test_json_with_comparison():
    r = analyze_bytes(build_synthetic_pe())
    data = json.loads(to_json(r, compare_reports(r, r)))
    assert data["comparison"]["identical"] is True


def _write(tmp_path: Path, name: str, data: bytes) -> str:
    p = tmp_path / name
    p.write_bytes(data)
    return str(p)


def test_cli_text(tmp_path, capsys):
    assert main([_write(tmp_path, "a.exe", build_synthetic_pe())]) == 0
    out = capsys.readouterr().out
    assert "SHA-256" in out and ".rand" in out and "high" in out


def test_cli_json_to_file_with_compare(tmp_path):
    a = _write(tmp_path, "a.exe", build_synthetic_pe())
    b = _write(tmp_path, "b.dll", build_synthetic_pe(dll=True))
    out = tmp_path / "r.json"
    assert main([a, "--compare", b, "--format", "json", "-o", str(out)]) == 0
    assert json.loads(out.read_text(encoding="utf-8"))["comparison"]["identical"] is False


def test_cli_markdown(tmp_path, capsys):
    assert main([_write(tmp_path, "a.exe", build_synthetic_pe()), "--format", "markdown"]) == 0
    assert capsys.readouterr().out.startswith("# PE report: a.exe")


def test_cli_bad_inputs(tmp_path, capsys):
    assert main([_write(tmp_path, "empty.exe", b"")]) == 2
    assert "empty" in capsys.readouterr().err
    assert main([_write(tmp_path, "t.exe", b"not a pe file at all" * 10)]) == 2
    assert main([str(tmp_path / "missing.exe")]) == 2
    good = _write(tmp_path, "g.exe", build_synthetic_pe())
    assert main([good, "--compare", _write(tmp_path, "bad.exe", b"MZ")]) == 2


def test_cli_unwritable_output(tmp_path, capsys):
    good = _write(tmp_path, "g.exe", build_synthetic_pe())
    assert main([good, "-o", str(tmp_path / "no" / "dir" / "x.txt")]) == 2
    assert "cannot write" in capsys.readouterr().err


def test_cli_refuses_to_overwrite_input(tmp_path, capsys):
    good = _write(tmp_path, "g.exe", build_synthetic_pe())
    before = Path(good).read_bytes()
    assert main([good, "-o", good]) == 2
    assert main([good, "-o", good, "--force"]) == 2
    other = _write(tmp_path, "o.exe", build_synthetic_pe(dll=True))
    assert main([good, "--compare", other, "-o", other, "--force"]) == 2
    assert "input file" in capsys.readouterr().err
    assert Path(good).read_bytes() == before


def test_cli_existing_output_needs_force(tmp_path, capsys):
    good = _write(tmp_path, "g.exe", build_synthetic_pe())
    out = tmp_path / "r.txt"
    out.write_text("old", encoding="utf-8")
    assert main([good, "-o", str(out)]) == 2
    assert "--force" in capsys.readouterr().err
    assert out.read_text(encoding="utf-8") == "old"
    assert main([good, "-o", str(out), "--force"]) == 0
    assert "SHA-256" in out.read_text(encoding="utf-8")


def test_markdown_neutralizes_hostile_strings():
    evil = b"<img src=x onerror=alert(1)> [click](http://evil) `x` **b** # h"
    md = to_markdown(analyze_bytes(build_synthetic_pe(text_string=evil)))
    assert "<img" not in md and "<" not in md.replace("&lt;", "")
    assert "[click]" not in md and "\\[click\\]" in md
    assert "\\*\\*b\\*\\*" in md
