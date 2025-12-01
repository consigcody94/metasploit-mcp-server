"""Tests for Metasploit RPC client."""

import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from metasploit_mcp.client import (
    MsfRpcClient,
    MsfRpcError,
    MsfAuthError,
    MsfConnectionError,
    MsfSession,
    MsfRpcMethod,
)
from metasploit_mcp.config import Settings


@pytest.fixture
def settings():
    """Create test settings."""
    return Settings(
        msf_host="127.0.0.1",
        msf_port=55553,
        msf_password="testpassword",
        msf_ssl=False,
        rate_limit_enabled=False,
    )


@pytest.fixture
def client(settings):
    """Create test client."""
    return MsfRpcClient(settings)


class TestMsfSession:
    """Test MsfSession dataclass."""

    def test_from_dict(self):
        """Test creating session from dict."""
        data = {
            "type": "meterpreter",
            "tunnel_local": "192.168.1.100:4444",
            "tunnel_peer": "192.168.1.200:54321",
            "via_exploit": "exploit/windows/smb/ms17_010_eternalblue",
            "via_payload": "payload/windows/meterpreter/reverse_tcp",
            "desc": "Meterpreter",
            "info": "NT AUTHORITY\\SYSTEM @ WIN-TARGET",
            "workspace": "default",
            "session_host": "192.168.1.200",
            "session_port": 445,
            "target_host": "192.168.1.200",
            "username": "SYSTEM",
            "uuid": "abc123",
            "exploit_uuid": "def456",
            "routes": [],
            "arch": "x64",
            "platform": "windows",
        }

        session = MsfSession.from_dict(1, data)

        assert session.id == 1
        assert session.type == "meterpreter"
        assert session.tunnel_local == "192.168.1.100:4444"
        assert session.via_exploit == "exploit/windows/smb/ms17_010_eternalblue"
        assert session.arch == "x64"
        assert session.platform == "windows"

    def test_from_dict_with_missing_fields(self):
        """Test creating session with missing optional fields."""
        data = {
            "type": "shell",
            "info": "root@target",
        }

        session = MsfSession.from_dict(2, data)

        assert session.id == 2
        assert session.type == "shell"
        assert session.info == "root@target"
        assert session.tunnel_local == ""
        assert session.routes == []


class TestMsfRpcClient:
    """Test MsfRpcClient class."""

    def test_initialization(self, client, settings):
        """Test client initialization."""
        assert client.settings == settings
        assert client._token is None
        assert client._connected is False

    def test_is_connected_initial(self, client):
        """Test is_connected property when not connected."""
        assert client.is_connected is False

    @pytest.mark.asyncio
    async def test_get_client_creates_http_client(self, client):
        """Test _get_client creates httpx client."""
        http_client = await client._get_client()

        assert http_client is not None
        assert client._client is http_client

        # Cleanup
        await http_client.aclose()

    @pytest.mark.asyncio
    async def test_connect_requires_password(self):
        """Test connect fails without password."""
        settings = Settings(msf_password="")
        client = MsfRpcClient(settings)

        with pytest.raises(MsfAuthError, match="No password configured"):
            await client.connect()

    @pytest.mark.asyncio
    async def test_disconnect_clears_state(self, client):
        """Test disconnect clears connection state."""
        client._token = "test_token"
        client._connected = True
        client._client = AsyncMock()
        client._client.aclose = AsyncMock()

        await client.disconnect()

        assert client._token is None
        assert client._connected is False
        assert client._client is None


class TestMsfRpcMethod:
    """Test MsfRpcMethod enum."""

    def test_auth_methods(self):
        """Test authentication methods."""
        assert MsfRpcMethod.AUTH_LOGIN.value == "auth.login"
        assert MsfRpcMethod.AUTH_LOGOUT.value == "auth.logout"

    def test_core_methods(self):
        """Test core methods."""
        assert MsfRpcMethod.CORE_VERSION.value == "core.version"
        assert MsfRpcMethod.CORE_MODULE_STATS.value == "core.module_stats"

    def test_module_methods(self):
        """Test module methods."""
        assert MsfRpcMethod.MODULE_EXPLOITS.value == "module.exploits"
        assert MsfRpcMethod.MODULE_EXECUTE.value == "module.execute"
        assert MsfRpcMethod.MODULE_SEARCH.value == "module.search"

    def test_session_methods(self):
        """Test session methods."""
        assert MsfRpcMethod.SESSION_LIST.value == "session.list"
        assert MsfRpcMethod.SESSION_METERPRETER_RUN_SINGLE.value == "session.meterpreter_run_single"

    def test_db_methods(self):
        """Test database methods."""
        assert MsfRpcMethod.DB_STATUS.value == "db.status"
        assert MsfRpcMethod.DB_HOSTS.value == "db.hosts"
        assert MsfRpcMethod.DB_VULNS.value == "db.vulns"


class TestMsfRpcErrors:
    """Test custom exceptions."""

    def test_msf_rpc_error(self):
        """Test MsfRpcError."""
        error = MsfRpcError("Test error", code=500, details={"key": "value"})

        assert str(error) == "Test error"
        assert error.message == "Test error"
        assert error.code == 500
        assert error.details == {"key": "value"}

    def test_msf_auth_error(self):
        """Test MsfAuthError."""
        error = MsfAuthError("Authentication failed")

        assert isinstance(error, MsfRpcError)
        assert str(error) == "Authentication failed"

    def test_msf_connection_error(self):
        """Test MsfConnectionError."""
        error = MsfConnectionError("Connection refused")

        assert isinstance(error, MsfRpcError)
        assert str(error) == "Connection refused"
