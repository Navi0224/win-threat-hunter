"""Turn raw log files into normalised ``Event`` objects.

Supported inputs
----------------
* ``.evtx``  - native Windows event log files (needs the ``python-evtx`` package)
* ``.jsonl`` - one JSON object per line (recommended export format, see README)
* ``.json``  - a JSON array of objects, or a single object (what
               ``Get-WinEvent | ConvertTo-Json`` produces)

Design choice: every parser converts to the same ``Event`` shape so the
detection engine never needs to know where data came from. Bad records are
*skipped and counted*, never fatal - real-world logs are messy and one broken
line must not hide an attack in the remaining million.
"""

from __future__ import annotations

import json
import re
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Iterator, Optional

from .models import Event

SUPPORTED_SUFFIXES = (".evtx", ".jsonl", ".json")

# Namespace used in every Windows event XML document.
_NS = "{http://schemas.microsoft.com/win/2004/08/events/event}"

# Windows PowerShell 5.1 serialises DateTime as "/Date(1700000000000)/".
_MS_DATE_RE = re.compile(r"^/Date\((-?\d+)([+-]\d{4})?\)/$")
# Windows timestamps often carry 7 fractional digits (100ns ticks). Python
# 3.10's fromisoformat only accepts exactly 3 or 6 digits, so we normalise
# the fraction to 6 digits (trim or pad).
_FRACTION_RE = re.compile(r"\.(\d+)")

# Keys we recognise for the top-level properties, in priority order.
_ID_KEYS = ("EventID", "EventId", "Id", "event_id")
_TIME_KEYS = ("TimeCreated", "Timestamp", "@timestamp", "timestamp", "SystemTime", "UtcTime")
_CHANNEL_KEYS = ("Channel", "LogName", "channel")
_PROVIDER_KEYS = ("Provider", "ProviderName", "provider")
_COMPUTER_KEYS = ("Computer", "MachineName", "computer", "Hostname")
_DATA_KEYS = ("EventData", "event_data", "Data")


@dataclass
class ParseStats:
    """Bookkeeping so the report can say how much data was really examined."""

    files: list[str] = field(default_factory=list)
    events: int = 0
    skipped: int = 0
    errors: list[str] = field(default_factory=list)


# --------------------------------------------------------------------------- #
# Timestamps
# --------------------------------------------------------------------------- #
def parse_timestamp(value: Any) -> datetime:
    """Parse the timestamp formats seen in Windows exports into aware UTC.

    Accepts ISO-8601 (with ``Z``, an offset, a space instead of ``T``, or 7
    fractional digits), and the ``/Date(ms)/`` form from PowerShell 5.1.
    Naive timestamps are assumed to be UTC - our export one-liner converts to
    UTC explicitly, which avoids time-zone bugs when correlating events.
    """
    if isinstance(value, datetime):
        dt = value
    elif isinstance(value, (int, float)):
        dt = datetime.fromtimestamp(float(value), tz=timezone.utc)
    elif isinstance(value, str):
        text = value.strip()
        ms = _MS_DATE_RE.match(text)
        if ms:
            dt = datetime.fromtimestamp(int(ms.group(1)) / 1000, tz=timezone.utc)
        else:
            text = text.replace(" ", "T", 1)
            if text.endswith("Z") or text.endswith("z"):
                text = text[:-1] + "+00:00"
            text = _FRACTION_RE.sub(lambda m: "." + m.group(1)[:6].ljust(6, "0"), text, count=1)
            dt = datetime.fromisoformat(text)
    elif isinstance(value, dict) and "DateTime" in value:
        # PowerShell sometimes wraps dates: {"value": "/Date(..)/", "DateTime": "..."}
        return parse_timestamp(value.get("value") or value["DateTime"])
    else:
        raise ValueError(f"unsupported timestamp: {value!r}")

    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


# --------------------------------------------------------------------------- #
# JSON / JSON lines
# --------------------------------------------------------------------------- #
def _first(obj: dict[str, Any], keys: Iterable[str]) -> Any:
    for key in keys:
        if key in obj and obj[key] not in (None, ""):
            return obj[key]
    return None


def _stringify(value: Any) -> str:
    """EventData values are compared as strings; keep that consistent."""
    if value is None:
        return ""
    if isinstance(value, (dict, list)):
        return json.dumps(value, ensure_ascii=False)
    return str(value)


def event_from_dict(obj: dict[str, Any], source: str = "") -> Event:
    """Build an ``Event`` from one exported JSON object.

    Raises ``ValueError`` if the object has no usable EventID or timestamp,
    because an event without those cannot be detected or correlated.
    """
    if not isinstance(obj, dict):
        raise ValueError("record is not a JSON object")

    raw_id = _first(obj, _ID_KEYS)
    if raw_id is None:
        raise ValueError("missing EventID")
    raw_time = _first(obj, _TIME_KEYS)
    if raw_time is None:
        raise ValueError("missing TimeCreated/timestamp")

    data_obj = _first(obj, _DATA_KEYS)
    if isinstance(data_obj, dict):
        data = {str(k): _stringify(v) for k, v in data_obj.items()}
    else:
        # Flat export: treat every non-metadata key as an EventData field.
        known = set(_ID_KEYS + _TIME_KEYS + _CHANNEL_KEYS + _PROVIDER_KEYS + _COMPUTER_KEYS + _DATA_KEYS)
        data = {str(k): _stringify(v) for k, v in obj.items() if k not in known}

    return Event(
        event_id=int(raw_id),
        timestamp=parse_timestamp(raw_time),
        channel=_stringify(_first(obj, _CHANNEL_KEYS)),
        provider=_stringify(_first(obj, _PROVIDER_KEYS)),
        computer=_stringify(_first(obj, _COMPUTER_KEYS)),
        data=data,
        source=source,
    )


def parse_jsonl(path: Path, stats: Optional[ParseStats] = None) -> Iterator[Event]:
    """Yield events from a JSON-lines file, skipping (and counting) bad lines."""
    stats = stats if stats is not None else ParseStats()
    # utf-8-sig strips the BOM that Windows PowerShell 5.1 adds with -Encoding utf8
    with path.open("r", encoding="utf-8-sig", errors="replace") as handle:
        for line_no, line in enumerate(handle, start=1):
            line = line.strip()
            if not line:
                continue
            try:
                yield event_from_dict(json.loads(line), source=f"{path.name}:{line_no}")
            except (ValueError, TypeError) as exc:  # JSONDecodeError is a ValueError
                stats.skipped += 1
                stats.errors.append(f"{path.name}:{line_no}: {exc}")


def parse_json(path: Path, stats: Optional[ParseStats] = None) -> Iterator[Event]:
    """Yield events from a .json file holding an array (or one object).

    Falls back to JSON-lines parsing if the file is not a single JSON document,
    because people often save JSON lines with a .json extension.
    """
    stats = stats if stats is not None else ParseStats()
    text = path.read_text(encoding="utf-8-sig", errors="replace")
    try:
        doc = json.loads(text)
    except json.JSONDecodeError:
        yield from parse_jsonl(path, stats)
        return
    records = doc if isinstance(doc, list) else [doc]
    for index, obj in enumerate(records, start=1):
        try:
            yield event_from_dict(obj, source=f"{path.name}#{index}")
        except (ValueError, TypeError) as exc:
            stats.skipped += 1
            stats.errors.append(f"{path.name}#{index}: {exc}")


# --------------------------------------------------------------------------- #
# EVTX
# --------------------------------------------------------------------------- #
def event_from_xml(xml_text: str, source: str = "") -> Event:
    """Convert one Windows event XML record (as stored in .evtx) to ``Event``.

    Most events keep their details in ``<EventData><Data Name=..>``. A few,
    such as 1102 "audit log cleared", use ``<UserData>`` with custom child
    elements instead, so we flatten those leaf elements too.
    """
    root = ET.fromstring(xml_text)
    system = root.find(f"{_NS}System")
    if system is None:
        raise ValueError("no <System> element")

    event_id_el = system.find(f"{_NS}EventID")
    time_el = system.find(f"{_NS}TimeCreated")
    if event_id_el is None or event_id_el.text is None or time_el is None:
        raise ValueError("missing EventID or TimeCreated")

    provider_el = system.find(f"{_NS}Provider")
    data: dict[str, str] = {}

    event_data = root.find(f"{_NS}EventData")
    if event_data is not None:
        for index, item in enumerate(event_data.findall(f"{_NS}Data")):
            name = item.get("Name") or f"Data{index}"
            data[name] = item.text or ""

    user_data = root.find(f"{_NS}UserData")
    if user_data is not None:
        for element in user_data.iter():
            if len(element) == 0 and element is not user_data:
                data[element.tag.split("}")[-1]] = element.text or ""

    return Event(
        event_id=int(event_id_el.text.strip()),
        timestamp=parse_timestamp(time_el.get("SystemTime", "")),
        channel=_text(system.find(f"{_NS}Channel")),
        provider=provider_el.get("Name", "") if provider_el is not None else "",
        computer=_text(system.find(f"{_NS}Computer")),
        data=data,
        source=source,
    )


def _text(element: Optional[ET.Element]) -> str:
    return (element.text or "").strip() if element is not None else ""


def parse_evtx(path: Path, stats: Optional[ParseStats] = None) -> Iterator[Event]:
    """Yield events from a binary .evtx file using python-evtx."""
    stats = stats if stats is not None else ParseStats()
    try:
        from Evtx.Evtx import Evtx  # imported lazily: only needed for .evtx
    except ImportError as exc:  # pragma: no cover - depends on environment
        raise RuntimeError("Reading .evtx needs python-evtx: pip install python-evtx") from exc

    with Evtx(str(path)) as log:
        for record in log.records():
            source = f"{path.name}:record{record.record_num()}"
            try:
                yield event_from_xml(record.xml(), source=source)
            except Exception as exc:  # noqa: BLE001 - corrupt records vary widely
                stats.skipped += 1
                stats.errors.append(f"{source}: {exc}")


# --------------------------------------------------------------------------- #
# Entry point used by the CLI
# --------------------------------------------------------------------------- #
def discover_files(paths: Iterable[Path]) -> list[Path]:
    """Expand directories into the supported log files they contain."""
    found: list[Path] = []
    for path in paths:
        if path.is_dir():
            found.extend(
                sorted(p for p in path.rglob("*") if p.is_file() and p.suffix.lower() in SUPPORTED_SUFFIXES)
            )
        elif path.is_file():
            found.append(path)
        else:
            raise FileNotFoundError(f"input not found: {path}")
    return found


def load_events(paths: Iterable[Path], stats: Optional[ParseStats] = None) -> list[Event]:
    """Load and time-sort events from files and/or directories."""
    stats = stats if stats is not None else ParseStats()
    events: list[Event] = []
    for path in discover_files(paths):
        suffix = path.suffix.lower()
        if suffix == ".evtx":
            reader = parse_evtx(path, stats)
        elif suffix == ".json":
            reader = parse_json(path, stats)
        else:  # .jsonl and anything else explicitly passed in
            reader = parse_jsonl(path, stats)
        before = len(events)
        events.extend(reader)
        stats.files.append(str(path))
        stats.events += len(events) - before
    # Correlation logic relies on chronological order.
    events.sort(key=lambda e: e.timestamp)
    return events
