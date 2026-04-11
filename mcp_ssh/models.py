from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Literal

from pydantic import BaseModel, Field


class AuthType(str, Enum):  # noqa: UP042
    agent                = "agent"
    key                  = "key"
    password             = "password"
    cert                 = "cert"
    sk                   = "sk"
    keyboard_interactive = "keyboard_interactive"
    gssapi               = "gssapi"


class HostKeyPolicy(str, Enum):  # noqa: UP042
    tofu       = "tofu"
    strict     = "strict"
    accept_new = "accept_new"


class ConnectionStatus(str, Enum):  # noqa: UP042
    connected    = "connected"
    disconnected = "disconnected"
    connecting   = "connecting"


class ProcessStatus(str, Enum):  # noqa: UP042
    running = "running"
    exited  = "exited"
    killed  = "killed"
    unknown = "unknown"


class ServerConfig(BaseModel):
    name:               str
    host:               str
    port:               int = 22
    user:               str
    auth_type:          AuthType
    key_path:           str | None = None
    cert_path:          str | None = None
    password_env:       str | None = None
    jump_host:          str | None = None       # name of another ServerConfig
    host_key_policy:    HostKeyPolicy | None = None  # None → use global default
    default_cwd:        str | None = None
    default_env:        dict[str, str] = Field(default_factory=dict)
    max_sessions:       int | None = None
    keepalive_interval: int | None = None


class GlobalSettings(BaseModel):
    known_hosts_file:        str = "~/.local/share/mcp-ssh/known_hosts"
    default_host_key_policy: HostKeyPolicy = HostKeyPolicy.tofu
    audit_log:               str = "~/.local/share/mcp-ssh/audit.jsonl"
    state_file:              str = "~/.local/share/mcp-ssh/state.json"
    max_sessions:            int = 10
    keepalive_interval:      int = 30
    keepalive_count_max:     int = 5
    connect_timeout:         int = 15
    default_encoding:        str = "utf-8"


class ProcessRecord(BaseModel):
    id:           str
    type:         Literal["exec"] = "exec"
    server:       str
    command:      str
    remote_pid:   int
    log_file:     str
    exit_file:    str
    started_at:   datetime
    last_checked: datetime | None = None
    status:       ProcessStatus = ProcessStatus.unknown
    exit_code:    int | None = None


class SessionRecord(BaseModel):
    id:           str
    type:         Literal["pty"] = "pty"
    server:       str
    command:      str | None
    use_tmux:     bool
    tmux_window:  str | None = None
    started_at:   datetime
    last_checked: datetime | None = None
    status:       ProcessStatus = ProcessStatus.unknown


class ProcessOutput(BaseModel):
    output:     str
    running:    bool
    exit_code:  int | None = None
    remote_pid: int
    server:     str


class PtyOutput(BaseModel):
    output: str
    alive:  bool


class AuditEvent(BaseModel):
    ts:         datetime
    tool:       str
    server:     str | None = None
    command:    str | None = None
    process_id: str | None = None
    session_id: str | None = None
    outcome:    str
    detail:     dict[str, object] = Field(default_factory=dict)
    # IMPORTANT: passwords, passphrases, env var values must NEVER appear here


class AppConfig(BaseModel):
    settings: GlobalSettings = Field(default_factory=GlobalSettings)
    servers:  dict[str, ServerConfig] = Field(default_factory=dict)
