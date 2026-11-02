"""Parsing: JSON lines, JSON arrays, PowerShell quirks, EVTX XML, bad input."""

from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path

import pytest

from wth.parsers import (
    ParseStats,
    discover_files,
    event_from_dict,
    event_from_xml,
    load_events,
    parse_json,
    parse_jsonl,
    parse_timestamp,
)

UTC = timezone.utc


@pytest.mark.parametrize(
    "raw, expected",
    [
        ("2026-10-30T14:01:02Z", datetime(2026, 10, 30, 14, 1, 2, tzinfo=UTC)),
        # Windows-style 7 fractional digits
        ("2026-10-30T14:01:02.1234567Z", datetime(2026, 10, 30, 14, 1, 2, 123456, tzinfo=UTC)),
        # Short fraction (Python 3.10 needs exactly 3 or 6 digits, so we pad)
        ("2026-10-30T14:01:02.5Z", datetime(2026, 10, 30, 14, 1, 2, 500000, tzinfo=UTC)),
        # Offset is converted to UTC (Malaysia is UTC+8)
        ("2026-10-30T22:01:02+08:00", datetime(2026, 10, 30, 14, 1, 2, tzinfo=UTC)),
        # Space separator as written by python-evtx
        ("2026-10-30 14:01:02.000000", datetime(2026, 10, 30, 14, 1, 2, tzinfo=UTC)),
        # Windows PowerShell 5.1 ConvertTo-Json date format (milliseconds since epoch)
        ("/Date(1793368862000)/", datetime(2026, 10, 30, 14, 1, 2, tzinfo=UTC)),
    ],
)
def test_parse_timestamp_formats(raw, expected):
    assert parse_timestamp(raw) == expected


def test_parse_timestamp_rejects_garbage():
    with pytest.raises(ValueError):
        parse_timestamp("not a date")


def test_event_from_dict_recommended_export_shape():
    event = event_from_dict(
        {
            "EventID": 4625,
            "TimeCreated": "2026-10-30T14:01:02Z",
            "Computer": "HOST1",
            "Channel": "Security",
            "Provider": "Microsoft-Windows-Security-Auditing",
            "EventData": {"TargetUserName": "bob", "LogonType": 3},
        }
    )
    assert event.event_id == 4625
    assert event.computer == "HOST1"
    assert event.data["LogonType"] == "3"  # values normalised to strings
    assert event.get("targetusername") == "bob"  # case-insensitive lookup
    assert event.get("EventID") == "4625"  # top-level fields reachable too


def test_event_from_dict_get_winevent_property_names():
    """Plain Get-WinEvent | ConvertTo-Json uses Id / TimeCreated / LogName / MachineName."""
    event = event_from_dict(
        {"Id": 1102, "TimeCreated": "/Date(1793368862000)/", "LogName": "Security", "MachineName": "HOST2"}
    )
    assert (event.event_id, event.channel, event.computer) == (1102, "Security", "HOST2")


def test_event_from_dict_flat_fields_become_data():
    event = event_from_dict({"EventID": 4720, "timestamp": "2026-01-01T00:00:00Z", "TargetUserName": "x"})
    assert event.data == {"TargetUserName": "x"}


@pytest.mark.parametrize("bad", [{"TimeCreated": "2026-01-01T00:00:00Z"}, {"EventID": 1}, ["not", "a", "dict"]])
def test_event_from_dict_rejects_incomplete_records(bad):
    with pytest.raises(ValueError):
        event_from_dict(bad)


def test_jsonl_skips_bad_lines_and_handles_bom(tmp_path: Path):
    good = {"EventID": 4624, "TimeCreated": "2026-01-01T00:00:00Z", "EventData": {}}
    content = "﻿" + json.dumps(good) + "\n{broken json\n\n" + json.dumps({"EventID": 1}) + "\n"
    path = tmp_path / "events.jsonl"
    path.write_text(content, encoding="utf-8")
    stats = ParseStats()
    events = list(parse_jsonl(path, stats))
    assert len(events) == 1
    assert stats.skipped == 2
    assert events[0].source == "events.jsonl:1"


def test_json_array_file(tmp_path: Path):
    records = [
        {"EventID": 4624, "TimeCreated": "2026-01-01T00:00:01Z"},
        {"EventID": 4625, "TimeCreated": "2026-01-01T00:00:00Z"},
    ]
    path = tmp_path / "export.json"
    path.write_text(json.dumps(records), encoding="utf-8")
    assert [e.event_id for e in parse_json(path)] == [4624, 4625]


def test_json_file_containing_json_lines_falls_back(tmp_path: Path):
    path = tmp_path / "actually_lines.json"
    path.write_text(
        '{"EventID": 1, "TimeCreated": "2026-01-01T00:00:00Z"}\n{"EventID": 2, "TimeCreated": "2026-01-01T00:00:00Z"}\n',
        encoding="utf-8",
    )
    assert len(list(parse_json(path))) == 2


def test_load_events_sorts_by_time_and_counts(tmp_path: Path):
    (tmp_path / "a.jsonl").write_text(
        '{"EventID": 2, "TimeCreated": "2026-01-01T00:00:05Z"}\n{"EventID": 1, "TimeCreated": "2026-01-01T00:00:01Z"}\n',
        encoding="utf-8",
    )
    (tmp_path / "ignored.txt").write_text("not a log", encoding="utf-8")
    stats = ParseStats()
    events = load_events([tmp_path], stats)
    assert [e.event_id for e in events] == [1, 2]
    assert stats.events == 2 and len(stats.files) == 1


def test_discover_files_missing_path():
    with pytest.raises(FileNotFoundError):
        discover_files([Path("definitely/not/here.jsonl")])


EVTX_XML_EVENTDATA = """<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Security-Auditing" Guid="{54849625-5478-4994-a5ba-3e3b0328c30d}"/>
    <EventID>4625</EventID>
    <TimeCreated SystemTime="2026-10-30T14:01:02.1234567Z"/>
    <Channel>Security</Channel>
    <Computer>WS-LAB-07</Computer>
  </System>
  <EventData>
    <Data Name="TargetUserName">administrator</Data>
    <Data Name="IpAddress">203.0.113.45</Data>
    <Data Name="LogonType">3</Data>
  </EventData>
</Event>"""

EVTX_XML_USERDATA = """<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Eventlog"/>
    <EventID Qualifiers="">1102</EventID>
    <TimeCreated SystemTime="2026-10-30 14:12:03.000000"/>
    <Channel>Security</Channel>
    <Computer>WS-LAB-07</Computer>
  </System>
  <UserData>
    <LogFileCleared xmlns="http://manifests.microsoft.com/win/2004/08/windows/eventlog">
      <SubjectUserSid>S-1-5-21-1-2-3-500</SubjectUserSid>
      <SubjectUserName>administrator</SubjectUserName>
    </LogFileCleared>
  </UserData>
</Event>"""


def test_event_from_xml_eventdata():
    event = event_from_xml(EVTX_XML_EVENTDATA, source="x.evtx:record1")
    assert event.event_id == 4625
    assert event.provider == "Microsoft-Windows-Security-Auditing"
    assert event.timestamp == datetime(2026, 10, 30, 14, 1, 2, 123456, tzinfo=UTC)
    assert event.data == {"TargetUserName": "administrator", "IpAddress": "203.0.113.45", "LogonType": "3"}


def test_event_from_xml_userdata_is_flattened():
    event = event_from_xml(EVTX_XML_USERDATA)
    assert event.event_id == 1102
    assert event.get("SubjectUserName") == "administrator"


def test_event_from_xml_rejects_non_event():
    with pytest.raises(ValueError):
        event_from_xml("<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'/>")


@pytest.mark.skipif(not os.environ.get("WTH_EVTX_DIR"), reason="set WTH_EVTX_DIR to a folder of real .evtx files")
def test_real_evtx_folder_parses():
    """Optional integration test against real .evtx files you provide."""
    stats = ParseStats()
    events = load_events([Path(os.environ["WTH_EVTX_DIR"])], stats)
    assert events, "no events parsed"
    assert all(e.event_id > 0 for e in events)
