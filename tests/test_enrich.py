"""Decoding of PowerShell -EncodedCommand payloads."""

from __future__ import annotations

import base64

import pytest

from wth.enrich import decode_powershell_command

SCRIPT = "Write-Output 'hello from a test'"
B64 = base64.b64encode(SCRIPT.encode("utf-16-le")).decode()


@pytest.mark.parametrize("flag", ["-e", "-ec", "-enc", "-EncodedCommand", "/enc", "-ENC"])
def test_decodes_all_flag_spellings(flag):
    assert decode_powershell_command(f"powershell.exe -nop {flag} {B64}") == SCRIPT


def test_ignores_commands_without_encoding():
    assert decode_powershell_command("powershell.exe -ExecutionPolicy Bypass -File x.ps1") is None


def test_invalid_base64_returns_none():
    assert decode_powershell_command("powershell -enc !!!!notbase64!!!!!!!!") is None
