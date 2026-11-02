"""Small enrichments that save an analyst time during triage.

Currently: decode PowerShell ``-EncodedCommand`` payloads. Attackers use
Base64 to hide what a command does; the first thing an analyst would do is
decode it, so we do it for them and attach the result as a note.
"""

from __future__ import annotations

import base64
import binascii
import re
from typing import Optional

from .models import Finding

# PowerShell accepts any unambiguous prefix of -EncodedCommand: -e, -ec, -en,
# -enc, -encodedcommand... Attackers rely on the short forms to dodge naive
# string matching, so the regex accepts all of them (and / as well as -).
ENCODED_ARG_RE = re.compile(
    r"(?:^|\s)[-/](?:e|ec|en|enc|enco|encod|encode|encoded|encodedc\w*)\s+([A-Za-z0-9+/=]{16,})",
    re.IGNORECASE,
)

_FIELDS_TO_CHECK = ("CommandLine", "ScriptBlockText", "ImagePath", "TaskContent")
_MAX_NOTE = 300


def decode_powershell_command(text: str) -> Optional[str]:
    """Return the decoded script hidden in an -EncodedCommand argument.

    PowerShell expects Base64 of **UTF-16LE** text (not UTF-8) - a detail
    worth knowing, because decoding as UTF-8 gives garbage with null bytes.
    """
    match = ENCODED_ARG_RE.search(text)
    if not match:
        return None
    blob = match.group(1)
    blob += "=" * (-len(blob) % 4)  # tolerate missing padding
    try:
        decoded = base64.b64decode(blob, validate=True).decode("utf-16-le")
    except (binascii.Error, UnicodeDecodeError, ValueError):
        return None
    decoded = decoded.strip()
    return decoded or None


def enrich_finding(finding: Finding) -> None:
    """Attach decoded payloads (deduplicated) to the finding's notes."""
    for event in finding.events:
        for field in _FIELDS_TO_CHECK:
            value = event.get(field)
            if not value:
                continue
            decoded = decode_powershell_command(value)
            if decoded:
                if len(decoded) > _MAX_NOTE:
                    decoded = decoded[: _MAX_NOTE - 3] + "..."
                note = f"Decoded -EncodedCommand ({field}): {decoded}"
                if note not in finding.notes:
                    finding.notes.append(note)
