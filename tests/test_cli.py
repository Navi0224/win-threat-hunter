"""End-to-end: run the CLI like a user would."""

from __future__ import annotations

import json

from wth.cli import main

from conftest import RULES_DIR, SAMPLES_DIR


def test_hunt_writes_all_reports(tmp_path, capsys):
    rc = main(
        [
            "hunt",
            str(SAMPLES_DIR / "sample_events.jsonl"),
            "--rules", str(RULES_DIR),
            "--json", str(tmp_path / "r.json"),
            "--markdown", str(tmp_path / "r.md"),
            "--html", str(tmp_path / "r.html"),
            "--no-color",
        ]
    )
    assert rc == 0
    assert json.loads((tmp_path / "r.json").read_text(encoding="utf-8"))["findings"]
    assert (tmp_path / "r.md").read_text(encoding="utf-8").startswith("# win-threat-hunter report")
    assert "<html" in (tmp_path / "r.html").read_text(encoding="utf-8")
    assert "WTH-002" in capsys.readouterr().out


def test_fail_on_returns_1_when_severe_findings(tmp_path):
    args = ["hunt", str(SAMPLES_DIR / "sample_events.jsonl"), "--rules", str(RULES_DIR), "--no-color"]
    assert main(args + ["--fail-on", "critical"]) == 1
    benign = ["hunt", str(SAMPLES_DIR / "benign_only.jsonl"), "--rules", str(RULES_DIR), "--no-color"]
    assert main(benign + ["--fail-on", "high"]) == 0


def test_list_rules(capsys):
    assert main(["list-rules", "--rules", str(RULES_DIR)]) == 0
    assert "11 rules" in capsys.readouterr().out


def test_missing_input_returns_2(capsys):
    assert main(["hunt", "no/such/file.jsonl", "--rules", str(RULES_DIR)]) == 2
    assert "error" in capsys.readouterr().err
