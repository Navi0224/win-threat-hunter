"""Load and validate YAML detection rules.

Validation is strict on purpose: a typo in a rule (e.g. ``opp: contains``)
would otherwise silently match nothing, and a detection that silently never
fires is one of the worst failure modes in a SOC. So we fail loudly, with the
file name and the problem.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any, Optional

import yaml

from .models import (
    SEVERITY_ORDER,
    Condition,
    Detection,
    Rule,
    Sequence,
    SequenceStep,
    Threshold,
)

VALID_OPS = ("equals", "contains", "startswith", "endswith", "regex", "exists")
_TECHNIQUE_RE = re.compile(r"^T\d{4}(\.\d{3})?$")


class RuleError(ValueError):
    """Raised when a rule file is malformed."""


def _require(data: dict[str, Any], key: str, where: str) -> Any:
    if key not in data or data[key] in (None, ""):
        raise RuleError(f"{where}: missing required key '{key}'")
    return data[key]


def _as_tuple(value: Any) -> tuple[str, ...]:
    """Allow 'x' or ['x', 'y'] in YAML; always return a tuple of strings."""
    if value is None:
        return ()
    if isinstance(value, (list, tuple)):
        return tuple(str(v) for v in value)
    return (str(value),)


def parse_condition(raw: dict[str, Any], where: str) -> Condition:
    if not isinstance(raw, dict):
        raise RuleError(f"{where}: each condition must be a mapping")
    fields = _as_tuple(_require(raw, "field", where))
    op = str(raw.get("op", "equals")).lower()
    if op not in VALID_OPS:
        raise RuleError(f"{where}: unknown op '{op}' (valid: {', '.join(VALID_OPS)})")
    values = _as_tuple(raw.get("value"))
    if op != "exists" and not values:
        raise RuleError(f"{where}: op '{op}' needs a 'value'")

    patterns: tuple[re.Pattern[str], ...] = ()
    if op == "regex":
        try:
            patterns = tuple(re.compile(v, re.IGNORECASE) for v in values)
        except re.error as exc:
            raise RuleError(f"{where}: bad regex: {exc}") from exc

    return Condition(
        fields=fields,
        op=op,
        # Compare case-insensitively: Windows paths and names are not case-sensitive,
        # and attackers deliberately use odd casing (PoWeRsHeLl.exe) to dodge matches.
        values=tuple(v.lower() for v in values),
        negate=bool(raw.get("negate", False)),
        patterns=patterns,
    )


def parse_detection(raw: dict[str, Any], where: str) -> Detection:
    if not isinstance(raw, dict):
        raise RuleError(f"{where}: 'detection' must be a mapping")
    event_ids = _require(raw, "event_ids", where)
    if not isinstance(event_ids, list):
        event_ids = [event_ids]
    try:
        ids = frozenset(int(i) for i in event_ids)
    except (TypeError, ValueError) as exc:
        raise RuleError(f"{where}: event_ids must be integers") from exc

    match = str(raw.get("match", "all")).lower()
    if match not in ("all", "any"):
        raise RuleError(f"{where}: match must be 'all' or 'any'")

    conditions = tuple(
        parse_condition(c, f"{where} condition {i + 1}") for i, c in enumerate(raw.get("conditions") or [])
    )
    channel = raw.get("channel")
    return Detection(event_ids=ids, conditions=conditions, match=match, channel=str(channel) if channel else None)


def _positive_int(raw: dict[str, Any], key: str, where: str) -> int:
    value = _require(raw, key, where)
    if not isinstance(value, int) or value < 1:
        raise RuleError(f"{where}: '{key}' must be a positive integer")
    return value


def parse_threshold(raw: dict[str, Any], where: str) -> Threshold:
    return Threshold(
        count=_positive_int(raw, "count", where),
        window_seconds=_positive_int(raw, "window_seconds", where),
        group_by=_as_tuple(raw.get("group_by")),
        distinct=str(raw["distinct"]) if raw.get("distinct") else None,
    )


def parse_sequence(raw: dict[str, Any], where: str) -> Sequence:
    steps_raw = _require(raw, "steps", where)
    if not isinstance(steps_raw, list) or len(steps_raw) < 2:
        raise RuleError(f"{where}: a sequence needs at least 2 steps")
    steps = []
    for i, step in enumerate(steps_raw, start=1):
        step_where = f"{where} step {i}"
        steps.append(
            SequenceStep(
                name=str(step.get("name", f"step{i}")),
                detection=parse_detection(step, step_where),
                min_count=int(step.get("min_count", 1)),
            )
        )
    return Sequence(
        steps=tuple(steps),
        window_seconds=_positive_int(raw, "window_seconds", where),
        group_by=_as_tuple(raw.get("group_by")),
    )


def parse_rule(raw: dict[str, Any], path: str = "<memory>") -> Rule:
    """Validate one rule dictionary (already loaded from YAML)."""
    if not isinstance(raw, dict):
        raise RuleError(f"{path}: rule file must contain a mapping")

    rule_id = str(_require(raw, "id", path))
    where = f"{path} [{rule_id}]"

    severity = str(_require(raw, "severity", where)).lower()
    if severity not in SEVERITY_ORDER:
        raise RuleError(f"{where}: severity must be one of {list(SEVERITY_ORDER)}")

    mitre = _require(raw, "mitre", where)
    technique_id = str(_require(mitre, "technique_id", f"{where} mitre"))
    if not _TECHNIQUE_RE.match(technique_id):
        raise RuleError(f"{where}: technique_id '{technique_id}' should look like T1110 or T1059.001")

    detection: Optional[Detection] = None
    sequence: Optional[Sequence] = None
    threshold: Optional[Threshold] = None
    if "sequence" in raw:
        if "detection" in raw:
            raise RuleError(f"{where}: use either 'detection' or 'sequence', not both")
        sequence = parse_sequence(raw["sequence"], f"{where} sequence")
    else:
        detection = parse_detection(_require(raw, "detection", where), f"{where} detection")
        if raw.get("threshold"):
            threshold = parse_threshold(raw["threshold"], f"{where} threshold")

    return Rule(
        id=rule_id,
        title=str(_require(raw, "title", where)),
        description=str(raw.get("description", "")).strip(),
        severity=severity,
        technique_id=technique_id,
        technique_name=str(_require(mitre, "technique_name", f"{where} mitre")),
        tactic=str(mitre.get("tactic", "")),
        response=str(_require(raw, "response", where)).strip(),
        detection=detection,
        threshold=threshold,
        sequence=sequence,
        false_positives=_as_tuple(raw.get("false_positives")),
        references=_as_tuple(raw.get("references")),
        path=path,
    )


def load_rule_file(path: Path) -> Rule:
    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8"))  # safe_load: never execute YAML tags
    except yaml.YAMLError as exc:
        raise RuleError(f"{path.name}: invalid YAML: {exc}") from exc
    return parse_rule(raw, path.name)


def load_rules(directory: Path) -> list[Rule]:
    """Load every *.yml / *.yaml file in a directory, rejecting duplicate IDs."""
    if not directory.is_dir():
        raise RuleError(f"rules directory not found: {directory}")
    files = sorted(list(directory.glob("*.yml")) + list(directory.glob("*.yaml")))
    rules = [load_rule_file(p) for p in files]
    seen: dict[str, str] = {}
    for rule in rules:
        if rule.id in seen:
            raise RuleError(f"duplicate rule id {rule.id} in {seen[rule.id]} and {rule.path}")
        seen[rule.id] = rule.path
    return rules
