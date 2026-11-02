"""Rule engine: field matching, threshold correlation, sequence correlation."""

from __future__ import annotations

from wth.engine import hunt, matches_condition, matches_detection, run_rule
from wth.rules import parse_condition, parse_detection, parse_rule

from conftest import make_event


def cond(**raw):
    return parse_condition(raw, "test")


# --------------------------------------------------------------------------- #
# Single-event matching
# --------------------------------------------------------------------------- #
def test_equals_is_case_insensitive():
    e = make_event(4732, TargetUserName="ADMINISTRATORS")
    assert matches_condition(e, cond(field="TargetUserName", op="equals", value="administrators"))


def test_value_list_is_or():
    e = make_event(1, Image=r"C:\Windows\System32\cmd.exe")
    c = cond(field="Image", op="endswith", value=[r"\powershell.exe", r"\cmd.exe"])
    assert matches_condition(e, c)


def test_field_list_is_or():
    e = make_event(4104, ScriptBlockText="IEX (New-Object Net.WebClient).DownloadString('x')")
    c = cond(field=["CommandLine", "ScriptBlockText"], op="contains", value="downloadstring")
    assert matches_condition(e, c)


def test_contains_startswith_regex_exists():
    e = make_event(4688, CommandLine="powershell -ec SQBFAFgAIAAoAE4AZQB3AC0A")
    assert matches_condition(e, cond(field="CommandLine", op="contains", value="-ec"))
    assert matches_condition(e, cond(field="CommandLine", op="startswith", value="POWERSHELL"))
    assert matches_condition(e, cond(field="CommandLine", op="regex", value=r"\s-e[a-z]*\s+[A-Za-z0-9+/=]{16,}"))
    assert matches_condition(e, cond(field="CommandLine", op="exists"))
    assert not matches_condition(e, cond(field="Nope", op="exists"))


def test_negate_and_missing_field():
    c = cond(field="IpAddress", op="equals", value=["-", ""], negate=True)
    assert matches_condition(make_event(4625, IpAddress="10.0.0.5"), c)
    assert not matches_condition(make_event(4625, IpAddress="-"), c)
    # Missing field: the positive test fails, so the negated test passes.
    assert matches_condition(make_event(4625), c)


def test_detection_checks_event_id_and_channel():
    det = parse_detection({"event_ids": [1], "channel": "Microsoft-Windows-Sysmon/Operational"}, "t")
    assert matches_detection(make_event(1, channel="Microsoft-Windows-Sysmon/Operational"), det)
    assert not matches_detection(make_event(1, channel="Application"), det)
    assert not matches_detection(make_event(2, channel="Microsoft-Windows-Sysmon/Operational"), det)


def test_match_all_vs_any():
    conditions = [
        {"field": "A", "op": "equals", "value": "1"},
        {"field": "B", "op": "equals", "value": "1"},
    ]
    e = make_event(10, A="1", B="2")
    assert not matches_detection(e, parse_detection({"event_ids": [10], "conditions": conditions}, "t"))
    assert matches_detection(e, parse_detection({"event_ids": [10], "match": "any", "conditions": conditions}, "t"))


# --------------------------------------------------------------------------- #
# Threshold correlation
# --------------------------------------------------------------------------- #
def threshold_rule(count=5, window=60, group_by=("IpAddress",), distinct=None):
    th = {"count": count, "window_seconds": window, "group_by": list(group_by)}
    if distinct:
        th["distinct"] = distinct
    return parse_rule(
        {
            "id": "TH",
            "title": "t",
            "severity": "medium",
            "mitre": {"technique_id": "T1110", "technique_name": "Brute Force"},
            "detection": {"event_ids": [4625]},
            "threshold": th,
            "response": "r",
        }
    )


def failures(n, ip="203.0.113.9", start=0, step=5, users=None):
    return [
        make_event(4625, start + i * step, IpAddress=ip, TargetUserName=(users[i] if users else "admin"))
        for i in range(n)
    ]


def test_threshold_below_count_does_not_fire():
    assert run_rule(threshold_rule(count=5), failures(4)) == []


def test_threshold_at_count_fires_once_with_group():
    findings = run_rule(threshold_rule(count=5), failures(5))
    assert len(findings) == 1
    assert findings[0].group == {"IpAddress": "203.0.113.9"}
    assert len(findings[0].events) == 5


def test_threshold_events_spread_beyond_window_do_not_fire():
    # 5 failures, but 30s apart -> never 5 inside a 60s window
    assert run_rule(threshold_rule(count=5, window=60), failures(5, step=30)) == []


def test_threshold_groups_are_separate():
    events = failures(3, ip="10.0.0.1") + failures(3, ip="10.0.0.2")
    assert run_rule(threshold_rule(count=5), events) == []


def test_threshold_burst_is_one_finding_not_many():
    """A long burst must produce one alert with all the evidence (alert fatigue)."""
    findings = run_rule(threshold_rule(count=5, window=60), failures(40, step=2))
    assert len(findings) == 1
    assert len(findings[0].events) == 40


def test_threshold_new_burst_after_quiet_period_fires_again():
    events = failures(5, start=0) + failures(5, start=1000)
    assert len(run_rule(threshold_rule(count=5, window=60), events)) == 2


def test_threshold_distinct_counts_unique_values():
    same_user = failures(6)
    many_users = failures(6, users=[f"user{i}" for i in range(6)])
    rule = threshold_rule(count=6, window=120, distinct="TargetUserName")
    assert run_rule(rule, same_user) == []
    assert len(run_rule(rule, many_users)) == 1


# --------------------------------------------------------------------------- #
# Sequence correlation
# --------------------------------------------------------------------------- #
def sequence_rule(min_count=3, window=300):
    return parse_rule(
        {
            "id": "SEQ",
            "title": "t",
            "severity": "critical",
            "mitre": {"technique_id": "T1110", "technique_name": "Brute Force"},
            "sequence": {
                "window_seconds": window,
                "group_by": ["IpAddress"],
                "steps": [
                    {"name": "fail", "event_ids": [4625], "min_count": min_count},
                    {"name": "success", "event_ids": [4624]},
                ],
            },
            "response": "r",
        }
    )


def success(seconds, ip="203.0.113.9"):
    return make_event(4624, seconds, IpAddress=ip, LogonType="3")


def test_sequence_fires_when_failures_then_success():
    findings = run_rule(sequence_rule(), failures(4) + [success(100)])
    assert len(findings) == 1
    # Evidence includes all 4 failures plus the success, success last
    assert [e.event_id for e in findings[0].events] == [4625] * 4 + [4624]


def test_sequence_wrong_order_does_not_fire():
    assert run_rule(sequence_rule(), [success(0)] + failures(4, start=10)) == []


def test_sequence_not_enough_failures():
    assert run_rule(sequence_rule(min_count=3), failures(2) + [success(100)]) == []


def test_sequence_outside_window_does_not_fire():
    assert run_rule(sequence_rule(window=60), failures(3) + [success(1000)]) == []


def test_sequence_different_ip_does_not_fire():
    assert run_rule(sequence_rule(), failures(3, ip="10.0.0.1") + [success(100, ip="10.0.0.2")]) == []


def test_sequence_does_not_reuse_evidence():
    # Two successes after one burst -> one finding, not two built from the same failures
    events = failures(3) + [success(100), success(110)]
    assert len(run_rule(sequence_rule(), events)) == 1


# --------------------------------------------------------------------------- #
# hunt()
# --------------------------------------------------------------------------- #
def test_hunt_sorts_by_severity_and_filters(rules):
    events = failures(12, step=5) + [success(70)]
    findings = hunt(rules, events)
    severities = [f.rule.severity for f in findings]
    assert severities[0] == "critical"
    assert [f.rule.id for f in hunt(rules, events, min_severity="critical")] == ["WTH-002"]
