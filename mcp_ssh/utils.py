"""Shared utility helpers for mcp_ssh."""
from __future__ import annotations

import re
from datetime import UTC, datetime

# Matches CSI sequences (ESC [ ... letter), OSC sequences (ESC ] ... ST),
# character-set designations (ESC ( x), and lone single-char escapes.
_ANSI_ESC_RE = re.compile(
    r"\x1b"
    r"(?:"
    r"\[[0-9;?]*[A-Za-z]"                    # CSI: ESC [ params letter
    r"|\][^\x07\x1b]*(?:\x07|\x1b\\)"        # OSC: ESC ] ... BEL|ST
    r"|[()][0-9A-Za-z]"                       # charset: ESC ( x
    r"|."                                     # any other single-char escape
    r")"
)


def strip_ansi(text: str) -> str:
    """Strip ANSI/VT100 escape sequences and normalize line endings.

    Removes all CSI, OSC, and escape sequences so output is plain text
    readable by both the AI (fewer tokens) and the Claude Code user.
    """
    text = _ANSI_ESC_RE.sub("", text)
    # Normalize \r\n -> \n and lone \r -> \n
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    return text


def now() -> datetime:
    """Return the current UTC time as a timezone-aware datetime."""
    return datetime.now(UTC)
