"""Tests for mcp_ssh.tools.pty_tools (T3c)."""
from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock

import pytest

from mcp_ssh.exceptions import (
    McpSshError,
    RemoteCommandError,
    SessionCapExceeded,
    SessionNotFound,
    TmuxNotAvailable,
)
from mcp_ssh.models import PtyOutput
from mcp_ssh.tools.pty_tools import (
    ssh_pty_attach,
    ssh_pty_close,
    ssh_pty_read,
    ssh_pty_resize,
    ssh_pty_write,
    ssh_start_pty,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

def _make_session_manager() -> AsyncMock:
    return AsyncMock()


def _make_audit() -> MagicMock:
    return MagicMock()


# ---------------------------------------------------------------------------
# ssh_start_pty
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_start_pty_success_no_tmux() -> None:
    sm = _make_session_manager()
    sm.start_pty = AsyncMock(return_value="sess-123")
    audit = _make_audit()
    result = await ssh_start_pty("srv1", sm, audit, use_tmux=False)
    assert result["session_id"] == "sess-123"
    assert result["use_tmux"] is False
    audit.log.assert_called_once()


@pytest.mark.asyncio
async def test_start_pty_success_with_tmux() -> None:
    sm = _make_session_manager()
    sm.start_pty = AsyncMock(return_value="sess-456")
    audit = _make_audit()
    result = await ssh_start_pty("srv1", sm, audit, use_tmux=True)
    assert result["session_id"] == "sess-456"
    assert result["use_tmux"] is True


@pytest.mark.asyncio
async def test_start_pty_tmux_not_available() -> None:
    """No silent fallback — tmux_not_available error returned."""
    sm = _make_session_manager()
    sm.start_pty = AsyncMock(side_effect=TmuxNotAvailable("tmux not found"))
    audit = _make_audit()
    result = await ssh_start_pty("srv1", sm, audit, use_tmux=True)
    assert result["error"] == "tmux_not_available"
    audit.log.assert_not_called()


@pytest.mark.asyncio
async def test_start_pty_session_cap_exceeded() -> None:
    sm = _make_session_manager()
    sm.start_pty = AsyncMock(side_effect=SessionCapExceeded("cap exceeded"))
    audit = _make_audit()
    result = await ssh_start_pty("srv1", sm, audit)
    assert result["error"] == "session_cap_exceeded"
    audit.log.assert_not_called()


@pytest.mark.asyncio
async def test_start_pty_passes_cols_rows() -> None:
    sm = _make_session_manager()
    sm.start_pty = AsyncMock(return_value="sess-789")
    audit = _make_audit()
    await ssh_start_pty("srv1", sm, audit, cols=132, rows=40)
    sm.start_pty.assert_called_once_with(
        server="srv1",
        command=None,
        cols=132,
        rows=40,
        use_tmux=False,
    )


# ---------------------------------------------------------------------------
# ssh_pty_read
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_pty_read_success() -> None:
    sm = _make_session_manager()
    sm.pty_read = AsyncMock(return_value=PtyOutput(output="hello", alive=True))
    result = await ssh_pty_read("s1", sm)
    assert result["output"] == "hello"
    assert result["alive"] is True


@pytest.mark.asyncio
async def test_pty_read_session_not_found() -> None:
    sm = _make_session_manager()
    sm.pty_read = AsyncMock(side_effect=SessionNotFound("nope"))
    result = await ssh_pty_read("gone", sm)
    assert result["error"] == "session_not_found"


# ---------------------------------------------------------------------------
# ssh_pty_write
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_pty_write_success() -> None:
    sm = _make_session_manager()
    sm.pty_write = AsyncMock(return_value=None)
    result = await ssh_pty_write("s1", "ls\r", sm)
    assert result["written"] is True
    sm.pty_write.assert_called_once_with("s1", "ls\r")


@pytest.mark.asyncio
async def test_pty_write_session_not_found() -> None:
    sm = _make_session_manager()
    sm.pty_write = AsyncMock(side_effect=SessionNotFound("nope"))
    result = await ssh_pty_write("gone", "data", sm)
    assert result["error"] == "session_not_found"


# ---------------------------------------------------------------------------
# ssh_pty_resize
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_pty_resize_success() -> None:
    sm = _make_session_manager()
    sm.pty_resize = AsyncMock(return_value=None)
    result = await ssh_pty_resize("s1", cols=120, rows=40, session_manager=sm)
    assert result["resized"] is True
    assert result["cols"] == 120
    assert result["rows"] == 40
    sm.pty_resize.assert_called_once_with("s1", cols=120, rows=40)


@pytest.mark.asyncio
async def test_pty_resize_session_not_found() -> None:
    sm = _make_session_manager()
    sm.pty_resize = AsyncMock(side_effect=SessionNotFound("nope"))
    result = await ssh_pty_resize("gone", cols=80, rows=24, session_manager=sm)
    assert result["error"] == "session_not_found"


# ---------------------------------------------------------------------------
# ssh_pty_close
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_pty_close_success() -> None:
    sm = _make_session_manager()
    sm.pty_close = AsyncMock(return_value=None)
    audit = _make_audit()
    result = await ssh_pty_close("s1", sm, audit)
    assert result["closed"] is True
    audit.log.assert_called_once()


@pytest.mark.asyncio
async def test_pty_close_session_not_found() -> None:
    sm = _make_session_manager()
    sm.pty_close = AsyncMock(side_effect=SessionNotFound("nope"))
    audit = _make_audit()
    result = await ssh_pty_close("gone", sm, audit)
    assert result["error"] == "session_not_found"
    audit.log.assert_not_called()


# ---------------------------------------------------------------------------
# ssh_pty_attach
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_pty_attach_non_tmux_returns_session_not_found() -> None:
    """Non-tmux sessions raise SessionNotFound from session manager."""
    sm = _make_session_manager()
    sm.pty_attach = AsyncMock(
        side_effect=SessionNotFound("pty_attach requires use_tmux=True")
    )
    result = await ssh_pty_attach("s1", sm)
    assert result["error"] == "session_not_found"


@pytest.mark.asyncio
async def test_pty_attach_not_supported_in_mcp() -> None:
    """pty_attach always raises NotImplementedError in MCP context."""
    sm = _make_session_manager()
    sm.pty_attach = AsyncMock(
        side_effect=NotImplementedError("not supported in MCP stdio context")
    )
    result = await ssh_pty_attach("s1", sm)
    assert result["error"] == "not_supported_in_mcp"


@pytest.mark.asyncio
async def test_pty_attach_tmux_window_missing() -> None:
    """tmux window gone → SessionNotFound from session manager → structured error."""
    sm = _make_session_manager()
    sm.pty_attach = AsyncMock(
        side_effect=SessionNotFound("tmux session no longer exists")
    )
    result = await ssh_pty_attach("s1", sm)
    assert result["error"] == "session_not_found"
    assert "tmux session" in result["message"] or "not found" in result["message"].lower()
