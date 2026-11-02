"""Command-line interface.

    wth hunt <files or folders> [--rules DIR] [--json F] [--markdown F] [--html F]
    wth list-rules [--rules DIR]

Exit codes: 0 = ran fine (with or without findings), 2 = usage/input error.
Use ``--fail-on high`` to exit 1 when a finding at/above that severity exists
(handy in scripts or CI pipelines).
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Optional, Sequence

from . import __version__
from .engine import hunt
from .models import SEVERITY_ORDER
from .parsers import ParseStats, load_events
from .report import RunInfo, print_console, write_html, write_json, write_markdown
from .rules import RuleError, load_rules


def default_rules_dir() -> Path:
    """Prefer ./rules (where the user is), else the repo's rules/ folder."""
    cwd_rules = Path.cwd() / "rules"
    if cwd_rules.is_dir():
        return cwd_rules
    return Path(__file__).resolve().parents[2] / "rules"


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="wth", description="Hunt for attacker behaviour in Windows Security/Sysmon/PowerShell logs."
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    hunt_p = sub.add_parser("hunt", help="run detection rules over log files")
    hunt_p.add_argument("inputs", nargs="+", type=Path, help=".evtx / .jsonl / .json files or folders")
    hunt_p.add_argument("--rules", type=Path, default=None, help="rules directory (default: ./rules)")
    hunt_p.add_argument("--json", type=Path, help="write JSON report to this path")
    hunt_p.add_argument("--markdown", type=Path, help="write Markdown report to this path")
    hunt_p.add_argument("--html", type=Path, help="write HTML report to this path")
    hunt_p.add_argument("--min-severity", choices=list(SEVERITY_ORDER), default="low")
    hunt_p.add_argument("--fail-on", choices=list(SEVERITY_ORDER), help="exit 1 if a finding >= this severity")
    hunt_p.add_argument("--no-color", action="store_true", help="disable coloured output")
    hunt_p.add_argument("-v", "--verbose", action="store_true", help="show response actions and decoded payloads")

    list_p = sub.add_parser("list-rules", help="show loaded rules and their ATT&CK mapping")
    list_p.add_argument("--rules", type=Path, default=None)
    return parser


def _cmd_list_rules(args: argparse.Namespace) -> int:
    rules = load_rules(args.rules or default_rules_dir())
    for r in rules:
        print(f"{r.id:<8} {r.severity:<8} {r.kind:<9} {r.technique_id:<10} {r.title}")
    print(f"{len(rules)} rules")
    return 0


def _cmd_hunt(args: argparse.Namespace) -> int:
    rules = load_rules(args.rules or default_rules_dir())
    stats = ParseStats()
    events = load_events(args.inputs, stats)
    findings = hunt(rules, events, min_severity=args.min_severity)

    info = RunInfo(
        inputs=[str(p) for p in args.inputs],
        events_parsed=stats.events,
        records_skipped=stats.skipped,
        rules_loaded=len(rules),
    )
    print_console(findings, info, color=not args.no_color, verbose=args.verbose)
    for err in stats.errors[:5]:
        print(f"warning: skipped {err}", file=sys.stderr)

    for path, writer in ((args.json, write_json), (args.markdown, write_markdown), (args.html, write_html)):
        if path:
            writer(findings, info, path)
            print(f"report written: {path}")

    if args.fail_on:
        floor = SEVERITY_ORDER[args.fail_on]
        if any(SEVERITY_ORDER[f.rule.severity] >= floor for f in findings):
            return 1
    return 0


def main(argv: Optional[Sequence[str]] = None) -> int:
    # Log data can contain any Unicode; on a Windows console with a legacy code
    # page, printing it could crash. Replace unprintable characters instead.
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(errors="replace")
    args = build_parser().parse_args(argv)
    try:
        if args.command == "list-rules":
            return _cmd_list_rules(args)
        return _cmd_hunt(args)
    except (RuleError, FileNotFoundError, RuntimeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
