from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

from . import __version__
from .analysis import PEInspectError, analyze_file
from .report import compare_reports, comparison_to_markdown, summary_rows, to_json, to_markdown


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="pe-inspector", description="Statically inspect a Windows PE (.exe/.dll) file."
    )
    p.add_argument("file", help="PE file to inspect")
    p.add_argument("--compare", metavar="OTHER", help="second PE file to compare against")
    p.add_argument("--format", choices=("text", "json", "markdown"), default="text", help="output format")
    p.add_argument("-o", "--output", help="write the report to this file instead of stdout")
    p.add_argument("--force", action="store_true", help="let -o overwrite an existing file")
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return p


def _text_report(report) -> str:
    lines = [f"{label + ':':<22}{value}" for label, value in summary_rows(report)]
    lines.append("")
    lines.append(f"{'Section':<10}{'VA':>10}{'RawSize':>10}  Perm  {'Entropy':>7}  Level")
    for s in report.sections:
        ent = "-" if s.entropy is None else f"{s.entropy:.3f}"
        va, raw = f"{s.virtual_address:#x}", f"{s.raw_size:#x}"
        lines.append(f"{s.name:<10}{va:>10}{raw:>10}  {s.permissions}  {ent:>7}  {s.entropy_level}")
    lines.append("")
    lines.append(
        f"Imports: {sum(len(d.functions) for d in report.imports)} from {len(report.imports)} DLLs; "
        f"exports: {len(report.exports)}; strings: {len(report.strings)}"
    )
    lines += [f"WARNING: {w}" for w in report.warnings]
    return "\n".join(lines)


def _same_file(a: str, b: str) -> bool:
    try:
        return os.path.samefile(a, b)
    except OSError:
        return False


def _check_output(args: argparse.Namespace) -> str | None:
    inputs = [args.file] + ([args.compare] if args.compare else [])
    if any(_same_file(args.output, p) for p in inputs):
        return "refusing to overwrite an input file"
    if os.path.exists(args.output) and not args.force:
        return f"{args.output} already exists (use --force to overwrite)"
    return None


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.output and (problem := _check_output(args)):
        print(f"error: {problem}", file=sys.stderr)
        return 2
    try:
        report = analyze_file(args.file)
        other = analyze_file(args.compare) if args.compare else None
    except PEInspectError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    comparison = compare_reports(report, other) if other else None
    if args.format == "json":
        text = to_json(report, comparison)
    elif args.format == "markdown":
        text = to_markdown(report, comparison)
    else:
        text = _text_report(report)
        if comparison:
            text += "\n\n" + comparison_to_markdown(comparison)

    if args.output:
        try:
            Path(args.output).write_text(text + "\n", encoding="utf-8")
        except OSError as exc:
            print(f"error: cannot write output: {exc.strerror or exc}", file=sys.stderr)
            return 2
    else:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        print(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
