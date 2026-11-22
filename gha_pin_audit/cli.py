"""Command-line entry point for gha-pin-audit."""

from __future__ import annotations

import argparse
import json
import sys

from . import __version__
from .core import DEFAULT_TRUSTED, audit_workflow, find_workflows

COLORS = {"error": "\033[31m", "warning": "\033[33m"}
RESET = "\033[0m"


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="gha-pin-audit",
        description="Audit GitHub Actions workflows for unpinned actions, broad token permissions "
        "and pull_request_target / script-injection pitfalls.",
    )
    p.add_argument("paths", nargs="*", default=["."], help="repo roots, workflow dirs or files (default: .)")
    p.add_argument(
        "--trust",
        action="append",
        default=[],
        metavar="OWNER",
        help=f"owner whose actions may use tags (repeatable; always trusted: {', '.join(DEFAULT_TRUSTED)})",
    )
    p.add_argument("--format", choices=["text", "json", "github"], default="text")
    p.add_argument("--strict", action="store_true", help="exit non-zero on warnings too")
    p.add_argument("--ignore", action="append", default=[], metavar="RULE", help="skip a rule id, e.g. PERM001")
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    files = find_workflows(args.paths)
    if not files:
        print("no workflow files found", file=sys.stderr)
        return 2
    trusted = DEFAULT_TRUSTED + tuple(args.trust)
    findings = []
    for f in files:
        findings += audit_workflow(f.read_text(encoding="utf-8"), str(f), trusted)
    findings = [f for f in findings if f.rule not in set(args.ignore)]

    errors = sum(f.severity == "error" for f in findings)
    warnings = len(findings) - errors
    if args.format == "json":
        print(json.dumps([f.to_dict() for f in findings], indent=2))
    elif args.format == "github":  # inline PR annotations
        for f in findings:
            print(f"::{f.severity} file={f.file},line={f.line},title={f.rule}::{f.message}")
    else:
        color = sys.stdout.isatty()
        for f in findings:
            sev = f"{COLORS[f.severity]}{f.severity}{RESET}" if color else f.severity
            print(f"{f.file}:{f.line}: {sev} [{f.rule}] {f.message}")
        print(f"\n{len(files)} workflow(s) scanned: {errors} error(s), {warnings} warning(s)")

    if errors or (args.strict and warnings):
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
