"""Tests for configuration module."""

import pytest
from pydantic import SecretStr

from metasploit_mcp.config import Settings, LogLevel, AuthMode


class TestSettings:
    """Test Settings class."""

    def test_default_settings(self):
        """Test default settings values."""
        settings = Settings()

        assert settings.msf_host == "127.0.0.1"
        assert settings.msf_port == 55553
        assert settings.msf_ssl is True
        assert settings.msf_username == "msf"
        assert settings.log_level == LogLevel.INFO

    def test_settings_from_env(self, monkeypatch):
        """Test settings from environment variables."""
        monkeypatch.setenv("METASPLOIT_MCP_MSF_HOST", "192.168.1.100")
        monkeypatch.setenv("METASPLOIT_MCP_MSF_PORT", "55554")
        monkeypatch.setenv("METASPLOIT_MCP_MSF_SSL", "false")
        monkeypatch.setenv("METASPLOIT_MCP_MSF_PASSWORD", "testpass")
        monkeypatch.setenv("METASPLOIT_MCP_LOG_LEVEL", "DEBUG")

        settings = Settings()

        assert settings.msf_host == "192.168.1.100"
        assert settings.msf_port == 55554
        assert settings.msf_ssl is False
        assert settings.msf_password.get_secret_value() == "testpass"
        assert settings.log_level == LogLevel.DEBUG

    def test_msf_url_construction(self):
        """Test MSF URL construction."""
        settings = Settings(msf_host="10.0.0.1", msf_port=55553, msf_ssl=True)
        assert settings.msf_url == "https://10.0.0.1:55553/api/"

        settings = Settings(msf_host="10.0.0.1", msf_port=55553, msf_ssl=False)
        assert settings.msf_url == "http://10.0.0.1:55553/api/"

    def test_module_allowed_default(self):
        """Test module allowance with defaults."""
        settings = Settings()

        # All modules allowed by default
        assert settings.is_module_allowed("exploit/windows/smb/ms17_010_eternalblue")
        assert settings.is_module_allowed("auxiliary/scanner/ssh/ssh_version")
        assert settings.is_module_allowed("post/windows/gather/hashdump")

    def test_module_blacklist(self):
        """Test module blacklist."""
        settings = Settings(blocked_modules="exploit/multi/handler,auxiliary/dos")

        assert settings.is_module_allowed("exploit/windows/smb/ms17_010_eternalblue")
        assert not settings.is_module_allowed("exploit/multi/handler")
        assert not settings.is_module_allowed("auxiliary/dos/tcp_synflood")

    def test_module_whitelist(self):
        """Test module whitelist."""
        settings = Settings(allowed_modules="auxiliary/scanner,exploit/windows")

        assert settings.is_module_allowed("auxiliary/scanner/ssh/ssh_version")
        assert settings.is_module_allowed("exploit/windows/smb/ms17_010_eternalblue")
        assert not settings.is_module_allowed("exploit/linux/ssh/sshkey_bruteforce")
        assert not settings.is_module_allowed("post/windows/gather/hashdump")

    def test_blocked_modules_from_string(self, monkeypatch):
        """Test parsing blocked modules from comma-separated string."""
        monkeypatch.setenv("METASPLOIT_MCP_BLOCKED_MODULES", "exploit/multi/handler,auxiliary/dos")

        settings = Settings()

        assert "exploit/multi/handler" in settings._blocked_modules_list
        assert "auxiliary/dos" in settings._blocked_modules_list
        assert not settings.is_module_allowed("exploit/multi/handler")

    def test_rate_limit_settings(self):
        """Test rate limit settings."""
        settings = Settings(
            rate_limit_enabled=True,
            rate_limit_calls=50,
            rate_limit_period=30.0,
        )

        assert settings.rate_limit_enabled is True
        assert settings.rate_limit_calls == 50
        assert settings.rate_limit_period == 30.0

    def test_feature_flags(self):
        """Test feature flag settings."""
        settings = Settings(
            enable_exploit_tools=False,
            enable_session_tools=False,
            enable_db_tools=True,
        )

        assert settings.enable_exploit_tools is False
        assert settings.enable_session_tools is False
        assert settings.enable_db_tools is True

    def test_safety_settings(self):
        """Test safety settings."""
        settings = Settings(
            dry_run_mode=True,
            require_confirmation=True,
            audit_logging=True,
        )

        assert settings.dry_run_mode is True
        assert settings.require_confirmation is True
        assert settings.audit_logging is True

    def test_password_secret_str(self):
        """Test that password is stored as SecretStr."""
        settings = Settings(msf_password="mysecretpassword")

        assert isinstance(settings.msf_password, SecretStr)
        assert settings.msf_password.get_secret_value() == "mysecretpassword"
        assert "mysecretpassword" not in str(settings.msf_password)
        assert "mysecretpassword" not in repr(settings.msf_password)


class TestLogLevel:
    """Test LogLevel enum."""

    def test_log_levels(self):
        """Test all log levels exist."""
        assert LogLevel.DEBUG == "DEBUG"
        assert LogLevel.INFO == "INFO"
        assert LogLevel.WARNING == "WARNING"
        assert LogLevel.ERROR == "ERROR"
        assert LogLevel.CRITICAL == "CRITICAL"


class TestAuthMode:
    """Test AuthMode enum."""

    def test_auth_modes(self):
        """Test all auth modes exist."""
        assert AuthMode.NONE == "none"
        assert AuthMode.TOKEN == "token"
        assert AuthMode.CERTIFICATE == "certificate"
