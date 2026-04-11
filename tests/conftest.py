"""Pytest configuration for mcp-ssh tests."""
import pytest


# Set pytest-asyncio mode to auto so all async test functions are collected
# as asyncio coroutines without needing explicit markers.
def pytest_configure(config: pytest.Config) -> None:
    config.addinivalue_line(
        "markers", "asyncio: mark test as asyncio"
    )
