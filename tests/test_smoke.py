"""Smoke tests — verify that the package structure is importable."""
from mcp_ssh import exceptions, interfaces, models


def test_models_classes_exist() -> None:
    """Core model classes must be importable."""
    assert hasattr(models, "AuthType")
    assert hasattr(models, "HostKeyPolicy")
    assert hasattr(models, "ConnectionStatus")
    assert hasattr(models, "ProcessStatus")
    assert hasattr(models, "ServerConfig")
    assert hasattr(models, "GlobalSettings")
    assert hasattr(models, "ProcessRecord")
    assert hasattr(models, "SessionRecord")
    assert hasattr(models, "ProcessOutput")
    assert hasattr(models, "PtyOutput")
    assert hasattr(models, "AuditEvent")
    assert hasattr(models, "AppConfig")


def test_interfaces_classes_exist() -> None:
    """Interface Protocol classes must be importable."""
    assert hasattr(interfaces, "IRegistry")
    assert hasattr(interfaces, "IConnectionPool")
    assert hasattr(interfaces, "ISessionManager")
    assert hasattr(interfaces, "IStateStore")
    assert hasattr(interfaces, "IAuditLog")


def test_exceptions_classes_exist() -> None:
    """Exception classes must be importable."""
    assert hasattr(exceptions, "McpSshError")
    assert hasattr(exceptions, "ServerNotFound")
    assert hasattr(exceptions, "ServerAlreadyExists")
    assert hasattr(exceptions, "ConnectionError")
    assert hasattr(exceptions, "AuthError")
    assert hasattr(exceptions, "HostKeyError")
    assert hasattr(exceptions, "SessionNotFound")
    assert hasattr(exceptions, "SessionCapExceeded")
    assert hasattr(exceptions, "ProcessNotFound")
    assert hasattr(exceptions, "TmuxNotAvailable")
    assert hasattr(exceptions, "RemoteCommandError")
