"""Core data structures shared by every module.

Keeping the data model in one small file makes the rest of the code easier to
follow: parsers *produce* ``Event`` objects, the rule loader produces ``Rule``
objects, and the engine turns both into ``Finding`` objects.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional

# Severity order is used for sorting findings and for --min-severity filtering.
SEVERITY_ORDER: dict[str, int] = {"low": 1, "medium": 2, "high": 3, "critical": 4}

# Fields an analyst usually wants to see first when looking at an event.
# Used only for building short human-readable summaries.
INTERESTING_FIELDS: tuple[str, ...] = (
    "TargetUserName",
    "SubjectUserName",
    "MemberName",
    "IpAddress",
    "LogonType",
    "User",
    "ParentImage",
    "Image",
    "NewProcessName",
    "CommandLine",
    "ServiceName",
    "ImagePath",
    "TaskName",
    "ScriptBlockText",
)


@dataclass(frozen=True)
class Event:
    """One normalised Windows event, regardless of whether it came from
    an .evtx file or from a JSON export.

    ``data`` holds the EventData / UserData name->value pairs, which is where
    the security-relevant details live (user names, IPs, command lines...).
    """

    event_id: int
    timestamp: datetime  # always timezone-aware, UTC
    channel: str = ""
    provider: str = ""
    computer: str = ""
    data: dict[str, str] = field(default_factory=dict)
    source: str = ""  # "file:line" or "file:record" so evidence is traceable

    def get(self, name: str) -> Optional[str]:
        """Return a field value by name.

        Top-level properties (EventID, Channel, ...) are reachable too, so a
        rule can say ``field: Computer`` without caring where it is stored.
        Lookup is case-insensitive because exports are not consistent.
        """
        top_level = {
            "eventid": str(self.event_id),
            "channel": self.channel,
            "provider": self.provider,
            "computer": self.computer,
        }
        key = name.lower()
        if key in top_level:
            return top_level[key]
        if name in self.data:
            return self.data[name]
        for k, v in self.data.items():
            if k.lower() == key:
                return v
        return None

    def summary(self, max_fields: int = 4, max_len: int = 120) -> str:
        """Short ``key=value`` string for tables and reports."""
        parts: list[str] = []
        for name in INTERESTING_FIELDS:
            value = self.data.get(name)
            if value and value != "-":
                parts.append(f"{name}={_shorten(value, max_len)}")
            if len(parts) >= max_fields:
                break
        if not parts:  # fall back to whatever fields exist
            for name, value in list(self.data.items())[:max_fields]:
                parts.append(f"{name}={_shorten(str(value), max_len)}")
        return "; ".join(parts)


def _shorten(text: str, max_len: int) -> str:
    text = re.sub(r"\s+", " ", text).strip()
    return text if len(text) <= max_len else text[: max_len - 3] + "..."


@dataclass(frozen=True)
class Condition:
    """A single test against one or more event fields.

    ``fields``  - checked with OR (useful when the same data has different
                  names in different logs, e.g. ScriptBlockText vs CommandLine)
    ``values``  - checked with OR (any value may match)
    ``negate``  - invert the result (used for exclusions / allow-listing)
    """

    fields: tuple[str, ...]
    op: str
    values: tuple[str, ...] = ()
    negate: bool = False
    patterns: tuple[re.Pattern[str], ...] = ()  # pre-compiled when op == regex


@dataclass(frozen=True)
class Detection:
    """Which events a rule (or a sequence step) is interested in."""

    event_ids: frozenset[int]
    conditions: tuple[Condition, ...] = ()
    match: str = "all"  # "all" = AND the conditions, "any" = OR them
    channel: Optional[str] = None


@dataclass(frozen=True)
class Threshold:
    """Correlation: fire only when ``count`` matching events occur within
    ``window_seconds`` for the same ``group_by`` key (e.g. same source IP).

    If ``distinct`` is set, count *distinct values* of that field instead of
    raw events (e.g. distinct user names -> password spraying).
    """

    count: int
    window_seconds: int
    group_by: tuple[str, ...] = ()
    distinct: Optional[str] = None


@dataclass(frozen=True)
class SequenceStep:
    name: str
    detection: Detection
    min_count: int = 1


@dataclass(frozen=True)
class Sequence:
    """Correlation: steps must happen *in order*, inside one time window,
    for the same group key (e.g. many failures THEN a success from one IP)."""

    steps: tuple[SequenceStep, ...]
    window_seconds: int
    group_by: tuple[str, ...] = ()


@dataclass(frozen=True)
class Rule:
    id: str
    title: str
    description: str
    severity: str
    technique_id: str
    technique_name: str
    tactic: str
    response: str
    detection: Optional[Detection] = None
    threshold: Optional[Threshold] = None
    sequence: Optional[Sequence] = None
    false_positives: tuple[str, ...] = ()
    references: tuple[str, ...] = ()
    path: str = ""

    @property
    def attack_url(self) -> str:
        """Link to the technique page, e.g. T1059.001 -> .../T1059/001/"""
        return "https://attack.mitre.org/techniques/" + self.technique_id.replace(".", "/") + "/"

    @property
    def kind(self) -> str:
        if self.sequence:
            return "sequence"
        if self.threshold:
            return "threshold"
        return "single"


@dataclass
class Finding:
    """An alert: one rule matched, with the events that prove it."""

    rule: Rule
    events: list[Event]
    group: dict[str, str] = field(default_factory=dict)
    notes: list[str] = field(default_factory=list)

    @property
    def first_seen(self) -> datetime:
        return min(e.timestamp for e in self.events)

    @property
    def last_seen(self) -> datetime:
        return max(e.timestamp for e in self.events)

    @property
    def computers(self) -> list[str]:
        return sorted({e.computer for e in self.events if e.computer})

    def describe(self, max_fields: int = 4, max_len: int = 120) -> str:
        """One-line human description used in every output format."""
        if self.group:
            key = ", ".join(f"{k}={v}" for k, v in self.group.items())
            return f"{len(self.events)} event(s) for {key}"
        return self.events[0].summary(max_fields=max_fields, max_len=max_len)
