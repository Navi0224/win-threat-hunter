"""Every shipped rule against the synthetic sample data.

These are "detection unit tests": if someone edits a rule and breaks it, the
exact expected count changes and the test fails - the same idea as
detection-as-code pipelines used by real SOC teams.
"""

from __future__ import annotations

from collections import Counter

import pytest

from wth.engine import hunt, run_rule

# Expected number of findings per rule on samples/sample_events.jsonl
EXPECTED = {
    "WTH-001": 1,  # 12 failed logons from 203.0.113.45
    "WTH-002": 1,  # ...followed by RDP success
    "WTH-003": 1,  # spray of 8 users from 198.51.100.23
    "WTH-004": 1,  # support_tmp created
    "WTH-005": 1,  # support_tmp added to Administrators (not the benign Event Log Readers add)
    "WTH-006": 1,  # Security log cleared
    "WTH-007": 3,  # Sysmon 1 (-ec), 4688 (-enc), 4104 (download cradle)
    "WTH-008": 2,  # benign Contoso service + malicious WinUpdateHelper
    "WTH-009": 1,  # only the malicious service
    "WTH-010": 2,  # benign updater task + malicious UpdateCheck task
    "WTH-011": 1,  # WINWORD -> powershell (not WINWORD -> splwow64)
}


def test_expected_table_covers_every_rule(rules):
    assert set(EXPECTED) == {r.id for r in rules}


@pytest.mark.parametrize("rule_id, expected", sorted(EXPECTED.items()))
def test_rule_fires_expected_times_on_samples(rule_id, expected, rules_by_id, sample_events):
    findings = run_rule(rules_by_id[rule_id], sample_events)
    assert len(findings) == expected


def test_brute_force_evidence_and_group(rules_by_id, sample_events):
    (finding,) = run_rule(rules_by_id["WTH-001"], sample_events)
    assert finding.group == {"IpAddress": "203.0.113.45"}
    assert len(finding.events) == 12


def test_benign_typos_and_console_failures_are_not_brute_force(rules_by_id, sample_events):
    for finding in run_rule(rules_by_id["WTH-001"], sample_events):
        assert finding.group["IpAddress"] not in ("10.0.0.15", "-")


def test_brute_force_then_success_ends_with_4624(rules_by_id, sample_events):
    (finding,) = run_rule(rules_by_id["WTH-002"], sample_events)
    assert finding.events[-1].event_id == 4624
    assert finding.events[-1].get("TargetUserName") == "administrator"


def test_spray_counts_distinct_users(rules_by_id, sample_events):
    (finding,) = run_rule(rules_by_id["WTH-003"], sample_events)
    assert len({e.get("TargetUserName") for e in finding.events}) == 8


def test_suspicious_service_is_the_malicious_one(rules_by_id, sample_events):
    (finding,) = run_rule(rules_by_id["WTH-009"], sample_events)
    assert finding.events[0].get("ServiceName") == "WinUpdateHelper"


def test_encoded_powershell_is_decoded_in_notes(rules, sample_events):
    findings = [f for f in hunt(rules, sample_events) if f.rule.id == "WTH-007"]
    assert any("DownloadString('http://203.0.113.45/stage2.ps1')" in n for f in findings for n in f.notes)


def test_total_findings_on_samples(rules, sample_events):
    findings = hunt(rules, sample_events)
    assert len(findings) == sum(EXPECTED.values())
    assert Counter(f.rule.severity for f in findings)["critical"] == 1


def test_benign_noise_has_no_high_or_critical_findings(rules, benign_events):
    """Benign activity may produce low/medium triage items, never high/critical."""
    findings = hunt(rules, benign_events)
    assert {f.rule.id for f in findings} == {"WTH-008", "WTH-010"}
    assert all(f.rule.severity in ("low", "medium") for f in findings)
