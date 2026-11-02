"""Report writers: JSON structure, Markdown links, HTML escaping, console."""

from __future__ import annotations

import io
import json

from wth.engine import hunt
from wth.models import Finding
from wth.report import (
    RunInfo,
    evidence_sample,
    print_console,
    render_html,
    render_markdown,
    write_json,
)

from conftest import make_event


def info() -> RunInfo:
    return RunInfo(inputs=["test"], events_parsed=1, records_skipped=0, rules_loaded=1)


def test_json_report_structure(tmp_path, rules, sample_events):
    findings = hunt(rules, sample_events)
    out = tmp_path / "r.json"
    write_json(findings, info(), out)
    data = json.loads(out.read_text(encoding="utf-8"))
    assert len(data["findings"]) == len(findings)
    first = data["findings"][0]
    for key in ("rule_id", "severity", "mitre", "evidence", "recommended_response", "first_seen"):
        assert key in first
    assert first["mitre"]["url"].startswith("https://attack.mitre.org/techniques/")


def test_markdown_has_attack_links_and_responses(rules, sample_events):
    md = render_markdown(hunt(rules, sample_events), info())
    assert "[T1110](https://attack.mitre.org/techniques/T1110/)" in md
    assert "**Recommended response:**" in md


def test_html_escapes_attacker_controlled_values(rules_by_id):
    """A malicious user name must not become live HTML in the analyst's browser."""
    evil = make_event(4720, TargetUserName="<script>alert(1)</script>")
    html_text = render_html([Finding(rule=rules_by_id["WTH-004"], events=[evil])], info())
    assert "<script>alert(1)</script>" not in html_text
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in html_text


def test_markdown_escapes_pipes(rules_by_id):
    e = make_event(4720, TargetUserName="a|b")
    md = render_markdown([Finding(rule=rules_by_id["WTH-004"], events=[e])], info())
    assert "a\\|b" in md


def test_evidence_sample_keeps_first_and_last():
    events = [make_event(4625, i) for i in range(25)]
    head, tail, omitted = evidence_sample(events, limit=10)
    assert head[0] is events[0] and tail[-1] is events[-1]
    assert len(head) + len(tail) == 10 and omitted == 15


def test_console_output_plain_text_without_markup_injection(rules_by_id):
    e = make_event(4720, TargetUserName="[bold red]fake[/bold red]")
    buf = io.StringIO()
    print_console([Finding(rule=rules_by_id["WTH-004"], events=[e])], info(), color=False, stream=buf, width=200)
    assert "[bold red]fake" in buf.getvalue()


def test_empty_reports_say_no_findings():
    assert "No findings" in render_markdown([], info())
    assert "No findings" in render_html([], info())
