"""Rule loading and validation - broken rules must fail loudly."""

from __future__ import annotations

from pathlib import Path

import pytest

from wth.rules import RuleError, load_rules, parse_rule


def minimal_rule(**overrides):
    rule = {
        "id": "T-1",
        "title": "test",
        "severity": "low",
        "mitre": {"technique_id": "T1110", "technique_name": "Brute Force"},
        "detection": {"event_ids": [4625]},
        "response": "do something",
    }
    rule.update(overrides)
    return rule


def test_shipped_rules_load(rules):
    assert len(rules) >= 8
    assert len({r.id for r in rules}) == len(rules)


def test_every_shipped_rule_has_attack_mapping_and_response(rules):
    for r in rules:
        assert r.technique_id.startswith("T"), r.id
        assert r.attack_url.startswith("https://attack.mitre.org/techniques/T"), r.id
        assert r.response, r.id
        assert r.description, r.id


def test_attack_url_for_subtechnique():
    rule = parse_rule(minimal_rule(mitre={"technique_id": "T1059.001", "technique_name": "PowerShell"}))
    assert rule.attack_url == "https://attack.mitre.org/techniques/T1059/001/"


def test_minimal_rule_is_single_kind():
    assert parse_rule(minimal_rule()).kind == "single"


@pytest.mark.parametrize(
    "overrides, message",
    [
        ({"severity": "urgent"}, "severity"),
        ({"mitre": {"technique_id": "1110", "technique_name": "x"}}, "technique_id"),
        ({"response": ""}, "response"),
        ({"detection": {"event_ids": ["abc"]}}, "integers"),
        ({"detection": {"event_ids": [1], "conditions": [{"field": "X", "op": "like", "value": "a"}]}}, "unknown op"),
        ({"detection": {"event_ids": [1], "conditions": [{"field": "X", "op": "contains"}]}}, "needs a 'value'"),
        ({"detection": {"event_ids": [1], "conditions": [{"field": "X", "op": "regex", "value": "("}]}}, "bad regex"),
        ({"detection": {"event_ids": [1]}, "threshold": {"count": 0, "window_seconds": 60}}, "positive integer"),
        ({"sequence": {"window_seconds": 60, "steps": [{"event_ids": [1]}]}}, "both"),
    ],
)
def test_invalid_rules_are_rejected(overrides, message):
    with pytest.raises(RuleError, match=message):
        parse_rule(minimal_rule(**overrides))


def test_sequence_needs_two_steps():
    raw = minimal_rule()
    del raw["detection"]
    raw["sequence"] = {"window_seconds": 60, "steps": [{"event_ids": [1]}]}
    with pytest.raises(RuleError, match="at least 2 steps"):
        parse_rule(raw)


def test_duplicate_ids_rejected(tmp_path: Path):
    text = (
        "id: DUP\ntitle: t\nseverity: low\nmitre: {technique_id: T1110, technique_name: x}\n"
        "detection: {event_ids: [1]}\nresponse: r\n"
    )
    (tmp_path / "a.yml").write_text(text, encoding="utf-8")
    (tmp_path / "b.yml").write_text(text, encoding="utf-8")
    with pytest.raises(RuleError, match="duplicate"):
        load_rules(tmp_path)


def test_invalid_yaml_reports_file(tmp_path: Path):
    (tmp_path / "bad.yml").write_text("id: [unclosed\n", encoding="utf-8")
    with pytest.raises(RuleError, match="bad.yml"):
        load_rules(tmp_path)


def test_missing_rules_dir(tmp_path: Path):
    with pytest.raises(RuleError, match="not found"):
        load_rules(tmp_path / "nope")
