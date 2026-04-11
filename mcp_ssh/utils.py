"""Shared utility helpers for mcp_ssh."""
from __future__ import annotations

from datetime import UTC, datetime


def now() -> datetime:
    """Return the current UTC time as a timezone-aware datetime."""
    return datetime.now(UTC)
