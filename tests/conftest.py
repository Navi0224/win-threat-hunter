"""Shared fixtures and helpers for the test suite."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import pytest

from wth.models import Event
from wth.parsers import load_events
from wth.rules import load_rules

ROOT = Path(__file__).resolve().parents[1]
RULES_DIR = ROOT / "rules"
SAMPLES_DIR = ROOT / "samples"

T0 = datetime(2026, 1, 1, 12, 0, 0, tzinfo=timezone.utc)


def make_event(event_id: int, seconds: float = 0, channel: str = "Security", **data: Any) -> Event:
    """Tiny factory so tests read like the scenario they describe."""
    return Event(
        event_id=event_id,
        timestamp=T0 + timedelta(seconds=seconds),
        channel=channel,
        computer="TEST-HOST",
        data={k: str(v) for k, v in data.items()},
    )


@pytest.fixture(scope="session")
def rules():
    return load_rules(RULES_DIR)


@pytest.fixture(scope="session")
def rules_by_id(rules):
    return {r.id: r for r in rules}


@pytest.fixture(scope="session")
def sample_events():
    return load_events([SAMPLES_DIR / "sample_events.jsonl"])


@pytest.fixture(scope="session")
def benign_events():
    return load_events([SAMPLES_DIR / "benign_only.jsonl"])
