"""MCP server entrypoint for mcp-ssh."""
from __future__ import annotations

import argparse
import importlib.metadata


class Server:
    """MCP server that exposes SSH operations as tools.

    Wires together the registry, connection pool, session manager,
    state store, and audit log.
    """

    ...


def main() -> None:
    """Entrypoint for the mcp-ssh server."""
    parser = argparse.ArgumentParser(
        prog="mcp-ssh",
        description="MCP server exposing SSH operations as tools",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {importlib.metadata.version('mcp-ssh')}",
    )
    parser.parse_args()
