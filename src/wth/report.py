"""Output: console table, JSON, Markdown and HTML reports.

Security note: everything inside an event (user names, command lines, task
XML...) is **attacker-controlled text**. An attacker can create a user called
``<script>...</script>``. The HTML report therefore escapes every value with
``html.escape`` - otherwise our own report would become an XSS vector against
the analyst who opens it.
"""

from __future__ import annotations

import html
import json
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional, TextIO

from . import __version__
from .models import SEVERITY_ORDER, Event, Finding

MAX_EVIDENCE = 10  # evidence rows shown per finding in MD/HTML (JSON keeps all)

SEVERITY_COLOURS = {"critical": "bold white on red", "high": "bold red", "medium": "yellow", "low": "cyan"}


@dataclass
class RunInfo:
    """Context printed at the top of every report."""

    inputs: list[str]
    events_parsed: int
    records_skipped: int
    rules_loaded: int
    generated_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


def _iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def event_to_dict(event: Event) -> dict[str, Any]:
    return {
        "timestamp": _iso(event.timestamp),
        "event_id": event.event_id,
        "channel": event.channel,
        "provider": event.provider,
        "computer": event.computer,
        "source": event.source,
        "data": event.data,
    }


def finding_to_dict(finding: Finding) -> dict[str, Any]:
    rule = finding.rule
    return {
        "rule_id": rule.id,
        "title": rule.title,
        "severity": rule.severity,
        "mitre": {
            "technique_id": rule.technique_id,
            "technique_name": rule.technique_name,
            "tactic": rule.tactic,
            "url": rule.attack_url,
        },
        "first_seen": _iso(finding.first_seen),
        "last_seen": _iso(finding.last_seen),
        "computers": finding.computers,
        "group": finding.group,
        "event_count": len(finding.events),
        "summary": finding.describe(),
        "notes": finding.notes,
        "recommended_response": rule.response,
        "false_positives": list(rule.false_positives),
        "evidence": [event_to_dict(e) for e in finding.events],
    }


def evidence_sample(events: list[Event], limit: int = MAX_EVIDENCE) -> tuple[list[Event], list[Event], int]:
    """Split long evidence into (head, tail, omitted_count).

    We keep the FIRST and LAST events rather than just the first N: in a
    brute-force-then-success finding the most important event (the success)
    is the last one, and it must never be hidden by truncation.
    """
    if len(events) <= limit:
        return events, [], 0
    half = limit // 2
    return events[:half], events[-(limit - half):], len(events) - limit


def severity_counts(findings: list[Finding]) -> dict[str, int]:
    counts = Counter(f.rule.severity for f in findings)
    return {sev: counts.get(sev, 0) for sev in sorted(SEVERITY_ORDER, key=SEVERITY_ORDER.get, reverse=True)}


def build_report(findings: list[Finding], info: RunInfo) -> dict[str, Any]:
    return {
        "tool": "win-threat-hunter",
        "version": __version__,
        "generated_at": _iso(info.generated_at),
        "inputs": info.inputs,
        "events_parsed": info.events_parsed,
        "records_skipped": info.records_skipped,
        "rules_loaded": info.rules_loaded,
        "finding_counts": severity_counts(findings),
        "findings": [finding_to_dict(f) for f in findings],
    }


# --------------------------------------------------------------------------- #
# JSON
# --------------------------------------------------------------------------- #
def write_json(findings: list[Finding], info: RunInfo, path: Path) -> None:
    """Machine-readable output, e.g. for forwarding into a SIEM or a ticket."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(build_report(findings, info), indent=2, ensure_ascii=False), encoding="utf-8")


# --------------------------------------------------------------------------- #
# Markdown
# --------------------------------------------------------------------------- #
def _md(text: str) -> str:
    """Escape characters that would break a Markdown table cell."""
    return str(text).replace("\\", "\\\\").replace("|", "\\|").replace("\n", " ").replace("\r", " ")


def render_markdown(findings: list[Finding], info: RunInfo) -> str:
    lines = [
        "# win-threat-hunter report",
        "",
        f"- Generated: {_iso(info.generated_at)}",
        f"- Inputs: {', '.join(info.inputs)}",
        f"- Events parsed: {info.events_parsed} (skipped records: {info.records_skipped})",
        f"- Rules loaded: {info.rules_loaded}",
        f"- Findings: {len(findings)} "
        + "(" + ", ".join(f"{k}: {v}" for k, v in severity_counts(findings).items()) + ")",
        "",
        "## Summary",
        "",
        "| # | Severity | Rule | ATT&CK | First seen (UTC) | Events | Detail |",
        "|---|----------|------|--------|------------------|--------|--------|",
    ]
    for i, f in enumerate(findings, start=1):
        r = f.rule
        lines.append(
            f"| {i} | {r.severity.upper()} | {r.id} {_md(r.title)} | "
            f"[{r.technique_id}]({r.attack_url}) | {_iso(f.first_seen)} | {len(f.events)} | {_md(f.describe())} |"
        )
    lines.append("")
    lines.append("## Findings")
    for i, f in enumerate(findings, start=1):
        r = f.rule
        lines += [
            "",
            f"### {i}. [{r.severity.upper()}] {r.id} - {r.title}",
            "",
            f"- **MITRE ATT&CK:** [{r.technique_id} {r.technique_name}]({r.attack_url}) ({r.tactic})",
            f"- **Time window (UTC):** {_iso(f.first_seen)} -> {_iso(f.last_seen)}",
            f"- **Host(s):** {', '.join(f.computers) or 'unknown'}",
            f"- **Summary:** {_md(f.describe())}",
            f"- **Recommended response:** {_md(r.response)}",
        ]
        if r.false_positives:
            lines.append(f"- **Possible false positives:** {_md('; '.join(r.false_positives))}")
        for note in f.notes:
            lines.append(f"- **Note:** `{note.replace('`', chr(39))}`")
        lines += ["", "| Time (UTC) | EventID | Host | Details | Source |", "|---|---|---|---|---|"]
        head, tail, omitted = evidence_sample(f.events)
        for e in head:
            lines.append(_md_evidence_row(e))
        if omitted:
            lines.append(f"| ... | | | _{omitted} more event(s) - see the JSON report_ | |")
        for e in tail:
            lines.append(_md_evidence_row(e))
    if not findings:
        lines += ["", "No findings. (Absence of evidence is not evidence of absence - check log coverage.)"]
    return "\n".join(lines) + "\n"


def _md_evidence_row(e: Event) -> str:
    return f"| {_iso(e.timestamp)} | {e.event_id} | {_md(e.computer)} | {_md(e.summary())} | {_md(e.source)} |"


def write_markdown(findings: list[Finding], info: RunInfo, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(render_markdown(findings, info), encoding="utf-8")


# --------------------------------------------------------------------------- #
# HTML (self-contained, no external CSS/JS so it opens offline)
# --------------------------------------------------------------------------- #
_HTML_STYLE = """
body{font-family:Segoe UI,Arial,sans-serif;margin:2rem;color:#222;max-width:1200px}
table{border-collapse:collapse;width:100%;margin:.5rem 0 1.5rem}
th,td{border:1px solid #ccc;padding:.35rem .5rem;text-align:left;vertical-align:top;font-size:.9rem}
th{background:#f0f0f0}.sev{font-weight:bold;padding:.1rem .4rem;border-radius:3px;color:#fff}
.critical{background:#7b0000}.high{background:#c62828}.medium{background:#e69500}.low{background:#1976d2}
code{background:#f6f6f6;padding:.1rem .3rem;word-break:break-all}.finding{border-top:2px solid #ddd;padding-top:.5rem}
"""


def _h(text: Any) -> str:
    return html.escape(str(text), quote=True)


def render_html(findings: list[Finding], info: RunInfo) -> str:
    counts = ", ".join(f"{k}: {v}" for k, v in severity_counts(findings).items())
    out = [
        "<!DOCTYPE html><html lang='en'><head><meta charset='utf-8'>",
        "<title>win-threat-hunter report</title>",
        f"<style>{_HTML_STYLE}</style></head><body>",
        "<h1>win-threat-hunter report</h1>",
        f"<p>Generated {_h(_iso(info.generated_at))} &middot; {info.events_parsed} events parsed "
        f"({info.records_skipped} skipped) &middot; {info.rules_loaded} rules &middot; "
        f"{len(findings)} findings ({_h(counts)})</p>",
        f"<p>Inputs: {_h(', '.join(info.inputs))}</p>",
        "<h2>Summary</h2><table><tr><th>#</th><th>Severity</th><th>Rule</th><th>ATT&amp;CK</th>"
        "<th>First seen (UTC)</th><th>Events</th><th>Detail</th></tr>",
    ]
    for i, f in enumerate(findings, start=1):
        r = f.rule
        out.append(
            f"<tr><td><a href='#f{i}'>{i}</a></td><td><span class='sev {r.severity}'>{r.severity.upper()}</span></td>"
            f"<td>{_h(r.id)} {_h(r.title)}</td><td><a href='{_h(r.attack_url)}'>{_h(r.technique_id)}</a></td>"
            f"<td>{_iso(f.first_seen)}</td><td>{len(f.events)}</td><td>{_h(f.describe())}</td></tr>"
        )
    out.append("</table><h2>Findings</h2>")
    for i, f in enumerate(findings, start=1):
        r = f.rule
        out += [
            f"<div class='finding' id='f{i}'><h3>{i}. <span class='sev {r.severity}'>{r.severity.upper()}</span> "
            f"{_h(r.id)} &ndash; {_h(r.title)}</h3><ul>",
            f"<li><b>MITRE ATT&amp;CK:</b> <a href='{_h(r.attack_url)}'>{_h(r.technique_id)} "
            f"{_h(r.technique_name)}</a> ({_h(r.tactic)})</li>",
            f"<li><b>Time window (UTC):</b> {_iso(f.first_seen)} &rarr; {_iso(f.last_seen)}</li>",
            f"<li><b>Host(s):</b> {_h(', '.join(f.computers) or 'unknown')}</li>",
            f"<li><b>Summary:</b> {_h(f.describe())}</li>",
            f"<li><b>Recommended response:</b> {_h(r.response)}</li>",
        ]
        if r.false_positives:
            out.append(f"<li><b>Possible false positives:</b> {_h('; '.join(r.false_positives))}</li>")
        for note in f.notes:
            out.append(f"<li><b>Note:</b> <code>{_h(note)}</code></li>")
        out.append("</ul><table><tr><th>Time (UTC)</th><th>EventID</th><th>Host</th><th>Details</th><th>Source</th></tr>")
        head, tail, omitted = evidence_sample(f.events)
        out.extend(_html_evidence_row(e) for e in head)
        if omitted:
            out.append(f"<tr><td colspan='5'><i>... {omitted} more event(s) - see the JSON report</i></td></tr>")
        out.extend(_html_evidence_row(e) for e in tail)
        out.append("</table></div>")
    if not findings:
        out.append("<p>No findings. (Absence of evidence is not evidence of absence &ndash; check log coverage.)</p>")
    out.append("</body></html>")
    return "\n".join(out)


def _html_evidence_row(e: Event) -> str:
    return (
        f"<tr><td>{_iso(e.timestamp)}</td><td>{e.event_id}</td><td>{_h(e.computer)}</td>"
        f"<td><code>{_h(e.summary())}</code></td><td>{_h(e.source)}</td></tr>"
    )


def write_html(findings: list[Finding], info: RunInfo, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(render_html(findings, info), encoding="utf-8")


# --------------------------------------------------------------------------- #
# Console
# --------------------------------------------------------------------------- #
def print_console(
    findings: list[Finding],
    info: RunInfo,
    color: bool = True,
    verbose: bool = False,
    stream: Optional[TextIO] = None,
    width: Optional[int] = None,
) -> None:
    """Coloured table via ``rich`` if installed, plain text otherwise."""
    try:
        from rich.console import Console
        from rich.markup import escape
        from rich.table import Table
    except ImportError:  # rich is optional
        _print_plain(findings, info, verbose, stream)
        return

    console = Console(file=stream, no_color=not color, highlight=False, soft_wrap=False, width=width)
    console.print(
        f"[bold]win-threat-hunter[/bold] - {info.events_parsed} events parsed "
        f"({info.records_skipped} skipped), {info.rules_loaded} rules, {len(findings)} findings"
    )
    if not findings:
        console.print("[green]No findings.[/green]")
        return
    table = Table(show_lines=False, header_style="bold")
    for col in ("#", "Severity", "Rule", "ATT&CK", "First seen (UTC)", "Events", "Detail"):
        table.add_column(col, overflow="fold")
    for i, f in enumerate(findings, start=1):
        r = f.rule
        table.add_row(
            str(i),
            f"[{SEVERITY_COLOURS[r.severity]}]{r.severity.upper()}[/]",
            escape(f"{r.id} {r.title}"),
            r.technique_id,
            _iso(f.first_seen),
            str(len(f.events)),
            # Log content is attacker-controlled: escape it so text like
            # "[red]" in a user name is shown literally, not as rich markup.
            escape(f.describe(max_fields=2, max_len=60)),
        )
    console.print(table)
    console.print(", ".join(f"{k}: {v}" for k, v in severity_counts(findings).items()))
    if verbose:
        for i, f in enumerate(findings, start=1):
            console.print(f"\n[bold]{i}. {escape(f.rule.id + ' ' + f.rule.title)}[/bold]")
            console.print(f"   Response: {f.rule.response}", markup=False)
            for note in f.notes:
                console.print(f"   Note: {note}", markup=False)


def _print_plain(findings: list[Finding], info: RunInfo, verbose: bool, stream: Optional[TextIO]) -> None:
    import sys

    out = stream or sys.stdout
    print(f"win-threat-hunter - {info.events_parsed} events parsed, {len(findings)} findings", file=out)
    for i, f in enumerate(findings, start=1):
        r = f.rule
        print(
            f"{i:>3}  {r.severity.upper():<8} {r.id:<8} {r.technique_id:<10} {_iso(f.first_seen)}  "
            f"{r.title} - {f.describe(max_fields=3, max_len=60)}",
            file=out,
        )
        if verbose:
            print(f"     Response: {r.response}", file=out)
            for note in f.notes:
                print(f"     Note: {note}", file=out)
