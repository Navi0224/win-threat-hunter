"""The detection engine: match events against rules and produce findings.

Three kinds of rule are supported:

1. **single**    - every matching event is a finding (e.g. "audit log cleared").
2. **threshold** - N matching events within T seconds for the same key
                   (e.g. 10 failed logons from one IP in 5 minutes).
3. **sequence**  - ordered steps within T seconds for the same key
                   (e.g. many failed logons, THEN a successful one).

Threshold and sequence rules are *correlation*: a single failed logon is
normal (people mistype passwords), but a burst of them is a signal. That is
the main tool we have against false positives.
"""

from __future__ import annotations

from collections import defaultdict, deque
from datetime import datetime, timedelta
from typing import Iterable, Optional

from .enrich import enrich_finding
from .models import SEVERITY_ORDER, Condition, Detection, Event, Finding, Rule, Sequence, Threshold

# --------------------------------------------------------------------------- #
# Matching a single event
# --------------------------------------------------------------------------- #


def _value_matches(op: str, actual: str, cond: Condition) -> bool:
    """Apply one operator to one field value (already lower-cased)."""
    if op == "exists":
        return True
    if op == "regex":
        return any(p.search(actual) for p in cond.patterns)
    if op == "equals":
        return any(actual == v for v in cond.values)
    if op == "contains":
        return any(v in actual for v in cond.values)
    if op == "startswith":
        return any(actual.startswith(v) for v in cond.values)
    if op == "endswith":
        return any(actual.endswith(v) for v in cond.values)
    raise ValueError(f"unknown op {op}")  # rules.py validates, so this is a bug guard


def matches_condition(event: Event, cond: Condition) -> bool:
    """True if ANY of the condition's fields satisfies the operator.

    A missing field counts as "no match" (and therefore as a match when
    ``negate`` is set - e.g. "IpAddress is not '-'" is true if there is no IP).
    """
    hit = False
    for name in cond.fields:
        value = event.get(name)
        if value is None:
            continue
        if _value_matches(cond.op, value.lower(), cond):
            hit = True
            break
    return not hit if cond.negate else hit


def matches_detection(event: Event, det: Detection) -> bool:
    """Check EventID first (cheap), then channel, then field conditions."""
    if event.event_id not in det.event_ids:
        return False
    if det.channel and event.channel.lower() != det.channel.lower():
        return False
    if not det.conditions:
        return True
    results = (matches_condition(event, c) for c in det.conditions)
    return all(results) if det.match == "all" else any(results)


def _group_key(event: Event, fields: tuple[str, ...]) -> tuple[str, ...]:
    """The value(s) that correlated events must share, e.g. the source IP."""
    return tuple((event.get(f) or "-") for f in fields)


def _group_dict(fields: tuple[str, ...], key: tuple[str, ...]) -> dict[str, str]:
    return dict(zip(fields, key))


# --------------------------------------------------------------------------- #
# Rule types
# --------------------------------------------------------------------------- #


def run_single(rule: Rule, events: Iterable[Event]) -> list[Finding]:
    assert rule.detection is not None
    return [Finding(rule=rule, events=[e]) for e in events if matches_detection(e, rule.detection)]


def _window_size(window: deque[Event], threshold: Threshold) -> int:
    if threshold.distinct:
        return len({(e.get(threshold.distinct) or "").lower() for e in window})
    return len(window)


def run_threshold(rule: Rule, events: Iterable[Event]) -> list[Finding]:
    """Sliding-window count per group.

    Once a group crosses the threshold we raise ONE finding and keep adding
    further events from the same burst to it (until the group goes quiet for
    a full window). Without this, a 500-attempt brute force would create 50
    near-identical alerts and bury the analyst - classic alert fatigue.
    """
    assert rule.detection is not None and rule.threshold is not None
    th = rule.threshold
    window_len = timedelta(seconds=th.window_seconds)

    groups: dict[tuple[str, ...], list[Event]] = defaultdict(list)
    for event in events:
        if matches_detection(event, rule.detection):
            groups[_group_key(event, th.group_by)].append(event)

    findings: list[Finding] = []
    for key, group_events in groups.items():
        group_events.sort(key=lambda e: e.timestamp)
        window: deque[Event] = deque()
        active: Optional[Finding] = None
        for event in group_events:
            # Still inside an ongoing burst -> attach as extra evidence.
            if active is not None and event.timestamp - active.last_seen <= window_len:
                active.events.append(event)
                continue
            active = None

            window.append(event)
            # Drop events that are older than the window, measured from the newest.
            while window and event.timestamp - window[0].timestamp > window_len:
                window.popleft()

            if _window_size(window, th) >= th.count:
                active = Finding(rule=rule, events=list(window), group=_group_dict(th.group_by, key))
                findings.append(active)
                window.clear()
    return findings


def _match_steps_in_order(candidates: list[Event], seq: Sequence) -> Optional[list[Event]]:
    """Greedy check that the non-final steps appear in order with their
    minimum counts. Returns the evidence events, or None."""
    steps = seq.steps[:-1]
    used: list[Event] = []
    step_index, count = 0, 0
    for event in candidates:
        if step_index < len(steps) and matches_detection(event, steps[step_index].detection):
            used.append(event)
            count += 1
            if count >= steps[step_index].min_count:
                step_index, count = step_index + 1, 0
        # Keep collecting extra events of the step we just completed so the
        # evidence shows the whole burst, not just the minimum.
        elif step_index > 0 and matches_detection(event, steps[step_index - 1].detection):
            used.append(event)
    return used if step_index >= len(steps) else None


def run_sequence(rule: Rule, events: Iterable[Event]) -> list[Finding]:
    """For each event matching the LAST step, look back ``window_seconds``
    in the same group and check that earlier steps happened in order.

    Example: 4625 x5 (step 1) then 4624 (step 2) from the same IP means the
    password guessing probably *worked* - much more urgent than failures alone.
    """
    assert rule.sequence is not None
    seq = rule.sequence
    window_len = timedelta(seconds=seq.window_seconds)
    final = seq.steps[-1]

    groups: dict[tuple[str, ...], list[Event]] = defaultdict(list)
    for event in events:
        if any(matches_detection(event, s.detection) for s in seq.steps):
            groups[_group_key(event, seq.group_by)].append(event)

    findings: list[Finding] = []
    for key, group_events in groups.items():
        group_events.sort(key=lambda e: e.timestamp)
        consumed_until: Optional[datetime] = None  # avoid re-using evidence
        for index, event in enumerate(group_events):
            if not matches_detection(event, final.detection):
                continue
            if consumed_until is not None and event.timestamp <= consumed_until:
                continue
            earlier = [
                e
                for e in group_events[:index]
                if event.timestamp - e.timestamp <= window_len
                and (consumed_until is None or e.timestamp > consumed_until)
            ]
            evidence = _match_steps_in_order(earlier, seq)
            if evidence is not None:
                findings.append(
                    Finding(rule=rule, events=evidence + [event], group=_group_dict(seq.group_by, key))
                )
                consumed_until = event.timestamp
    return findings


# --------------------------------------------------------------------------- #
# Public API
# --------------------------------------------------------------------------- #


def run_rule(rule: Rule, events: list[Event]) -> list[Finding]:
    if rule.kind == "sequence":
        return run_sequence(rule, events)
    if rule.kind == "threshold":
        return run_threshold(rule, events)
    return run_single(rule, events)


def hunt(rules: Iterable[Rule], events: list[Event], min_severity: str = "low") -> list[Finding]:
    """Run every rule over the events; return findings, most severe first."""
    floor = SEVERITY_ORDER[min_severity]
    findings: list[Finding] = []
    for rule in rules:
        if SEVERITY_ORDER[rule.severity] < floor:
            continue
        for finding in run_rule(rule, events):
            enrich_finding(finding)
            findings.append(finding)
    findings.sort(key=lambda f: (-SEVERITY_ORDER[f.rule.severity], f.first_seen, f.rule.id))
    return findings
