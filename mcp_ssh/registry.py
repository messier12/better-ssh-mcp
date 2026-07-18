"""Server registry implementing IRegistry."""
from __future__ import annotations

import logging
import os
from collections.abc import AsyncIterator
from pathlib import Path

from .config import app_config_to_toml, load_config
from .exceptions import McpSshError, ServerAlreadyExists, ServerNotFound
from .models import AppConfig, ServerConfig

logger = logging.getLogger(__name__)


class Registry:
    """Registry of SSH server configurations, implementing IRegistry.

    Supports watching for file changes via ``watchfiles.awatch`` and
    atomic writes for ``add`` / ``remove`` operations.

    Parameters
    ----------
    config_path:
        Path to the ``servers.toml`` file.  Must already exist when the
        constructor is called (or be created before the first ``watch()``
        iteration).
    """

    def __init__(self, config_path: Path) -> None:
        self._config_path = config_path
        self._config: AppConfig = load_config(config_path)
        # In-memory, non-persisted server configs (e.g. spontaneous jump chains).
        # These live only for the process lifetime and survive config reloads.
        self._ephemeral: dict[str, ServerConfig] = {}

    # ------------------------------------------------------------------
    # IRegistry interface
    # ------------------------------------------------------------------

    def get(self, name: str) -> ServerConfig:
        """Return the ``ServerConfig`` for *name*.

        Ephemeral (in-memory) servers take precedence over file-backed ones.

        Raises:
            ServerNotFound: if no server with that name is registered.
        """
        if name in self._ephemeral:
            return self._ephemeral[name]
        try:
            return self._config.servers[name]
        except KeyError:
            raise ServerNotFound(f"Server '{name}' not found in registry") from None

    def list_all(self) -> list[ServerConfig]:
        """Return all registered server configurations (file-backed + ephemeral)."""
        return list(self._config.servers.values()) + list(self._ephemeral.values())

    def add(self, config: ServerConfig) -> None:
        """Add *config* to the registry and atomically persist the config file.

        Raises:
            ServerAlreadyExists: if a server with the same name already exists.
        """
        if config.name in self._config.servers or config.name in self._ephemeral:
            raise ServerAlreadyExists(
                f"Server '{config.name}' already exists in registry"
            )
        new_servers = {**self._config.servers, config.name: config}
        new_cfg = self._config.model_copy(update={"servers": new_servers})
        self._write_config(new_cfg)
        self._config = new_cfg

    def remove(self, name: str) -> None:
        """Remove the server named *name* and atomically persist the config file.

        Raises:
            ServerNotFound: if no server with that name is registered.
        """
        if name not in self._config.servers:
            raise ServerNotFound(f"Server '{name}' not found in registry")
        new_servers = {k: v for k, v in self._config.servers.items() if k != name}
        new_cfg = self._config.model_copy(update={"servers": new_servers})
        self._write_config(new_cfg)
        self._config = new_cfg

    def get_config(self) -> AppConfig:
        """Return the full ``AppConfig`` (settings + all servers)."""
        return self._config

    # ------------------------------------------------------------------
    # Ephemeral (in-memory, non-persisted) servers
    # ------------------------------------------------------------------

    def add_ephemeral(self, config: ServerConfig) -> None:
        """Register *config* in memory only — never written to the config file.

        Used for spontaneous, throwaway servers such as jump chains. Ephemeral
        entries survive config-file reloads and are resolved by ``get`` with
        precedence over file-backed servers.

        Raises:
            ServerAlreadyExists: if the name collides with any file-backed or
                ephemeral server.
        """
        if config.name in self._config.servers or config.name in self._ephemeral:
            raise ServerAlreadyExists(
                f"Server '{config.name}' already exists in registry"
            )
        self._ephemeral[config.name] = config

    def remove_ephemeral(self, name: str) -> None:
        """Remove the ephemeral server named *name*.

        Raises:
            ServerNotFound: if no ephemeral server with that name exists.
        """
        if name not in self._ephemeral:
            raise ServerNotFound(f"Ephemeral server '{name}' not found in registry")
        del self._ephemeral[name]

    def list_ephemeral(self) -> list[ServerConfig]:
        """Return all ephemeral (in-memory) server configurations."""
        return list(self._ephemeral.values())

    async def watch(self) -> AsyncIterator[None]:
        """Yield ``None`` every time the config file changes and reloads successfully.

        On parse / validation error the previous valid config is retained and the
        error is logged — the registry is **never** left in a broken state.

        This is an async generator; callers should use it with ``async for``:

        .. code-block:: python

            async for _ in registry.watch():
                # config was reloaded
                ...
        """
        import watchfiles  # lazy import so tests can patch easily

        async for _ in watchfiles.awatch(self._config_path):
            try:
                new_cfg = load_config(self._config_path)
            except McpSshError as exc:
                logger.error(
                    "Config reload failed — retaining previous valid config: %s", exc
                )
                continue
            self._config = new_cfg
            yield

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _write_config(self, cfg: AppConfig) -> None:
        """Atomically write *cfg* to ``self._config_path``.

        Uses the write-to-``.tmp``-then-``os.replace`` pattern so that a
        crash mid-write never leaves a corrupt config file on disk.
        """
        tmp_path = self._config_path.with_suffix(".tmp")
        toml_str = app_config_to_toml(cfg)
        try:
            tmp_path.parent.mkdir(parents=True, exist_ok=True)
            tmp_path.write_text(toml_str, encoding="utf-8")
            os.replace(tmp_path, self._config_path)
        except OSError as exc:
            raise McpSshError(
                f"Failed to write config to {self._config_path}: {exc}"
            ) from exc
