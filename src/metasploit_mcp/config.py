"""
Configuration management for Metasploit MCP Server.

Provides secure, type-safe configuration with environment variable support
and sensible defaults for penetration testing environments.
"""

from __future__ import annotations

from enum import Enum
from typing import Optional

from pydantic import Field, SecretStr, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class LogLevel(str, Enum):
    """Supported logging levels."""

    DEBUG = "DEBUG"
    INFO = "INFO"
    WARNING = "WARNING"
    ERROR = "ERROR"
    CRITICAL = "CRITICAL"


class AuthMode(str, Enum):
    """Authentication modes for MCP server."""

    NONE = "none"
    TOKEN = "token"
    CERTIFICATE = "certificate"


class Settings(BaseSettings):
    """
    Application settings with environment variable support.

    All settings can be configured via environment variables with the
    METASPLOIT_MCP_ prefix (e.g., METASPLOIT_MCP_HOST).
    """

    model_config = SettingsConfigDict(
        env_prefix="METASPLOIT_MCP_",
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # Metasploit RPC Connection Settings
    msf_host: str = Field(
        default="127.0.0.1", description="Metasploit RPC server hostname or IP address"
    )
    msf_port: int = Field(default=55553, ge=1, le=65535, description="Metasploit RPC server port")
    msf_ssl: bool = Field(default=True, description="Use SSL/TLS for RPC connection")
    msf_ssl_verify: bool = Field(
        default=False, description="Verify SSL certificate (disable for self-signed certs)"
    )
    msf_username: str = Field(default="msf", description="Metasploit RPC username")
    msf_password: SecretStr = Field(default=SecretStr(""), description="Metasploit RPC password")
    msf_token: Optional[str] = Field(
        default=None, description="Pre-existing authentication token (optional)"
    )
    msf_uri: str = Field(default="/api/", description="Metasploit RPC API URI path")

    # Connection Pool Settings
    connection_timeout: float = Field(
        default=30.0, ge=1.0, le=300.0, description="Connection timeout in seconds"
    )
    request_timeout: float = Field(
        default=120.0, ge=1.0, le=600.0, description="Request timeout in seconds"
    )
    max_retries: int = Field(
        default=3, ge=0, le=10, description="Maximum retry attempts for failed requests"
    )
    retry_delay: float = Field(
        default=1.0, ge=0.1, le=30.0, description="Delay between retry attempts in seconds"
    )

    # Rate Limiting
    rate_limit_enabled: bool = Field(default=True, description="Enable rate limiting for RPC calls")
    rate_limit_calls: int = Field(
        default=100, ge=1, le=1000, description="Maximum API calls per period"
    )
    rate_limit_period: float = Field(
        default=60.0, ge=1.0, le=3600.0, description="Rate limit period in seconds"
    )

    # MCP Server Settings
    server_name: str = Field(
        default="metasploit-mcp-server", description="MCP server name for identification"
    )
    server_version: str = Field(default="1.0.0", description="MCP server version")

    # Security Settings
    auth_mode: AuthMode = Field(
        default=AuthMode.NONE, description="Authentication mode for MCP clients"
    )
    auth_token: Optional[SecretStr] = Field(
        default=None, description="Authentication token for MCP clients (if auth_mode=token)"
    )
    allowed_modules: Optional[str] = Field(
        default=None,
        description="Whitelist of allowed Metasploit modules (comma-separated, None = all allowed)",
    )
    blocked_modules: str = Field(
        default="", description="Blacklist of blocked Metasploit modules (comma-separated)"
    )

    # Parsed module lists (internal)
    _allowed_modules_list: list[str] = []
    _blocked_modules_list: list[str] = []
    max_concurrent_sessions: int = Field(
        default=10, ge=1, le=100, description="Maximum concurrent Meterpreter/shell sessions"
    )
    session_timeout: int = Field(
        default=3600, ge=60, le=86400, description="Session timeout in seconds"
    )

    # Logging Settings
    log_level: LogLevel = Field(default=LogLevel.INFO, description="Logging level")
    log_file: Optional[str] = Field(default=None, description="Log file path (None = stdout only)")
    log_json: bool = Field(default=False, description="Output logs in JSON format")

    # Feature Flags
    enable_exploit_tools: bool = Field(default=True, description="Enable exploit execution tools")
    enable_payload_tools: bool = Field(default=True, description="Enable payload generation tools")
    enable_auxiliary_tools: bool = Field(default=True, description="Enable auxiliary module tools")
    enable_post_tools: bool = Field(default=True, description="Enable post-exploitation tools")
    enable_session_tools: bool = Field(default=True, description="Enable session management tools")
    enable_db_tools: bool = Field(default=True, description="Enable database/workspace tools")

    # Safety Settings
    require_confirmation: bool = Field(
        default=False, description="Require confirmation before executing exploits"
    )
    dry_run_mode: bool = Field(
        default=False, description="Enable dry-run mode (no actual exploitation)"
    )
    audit_logging: bool = Field(
        default=True, description="Enable detailed audit logging of all operations"
    )

    @field_validator("msf_password", mode="before")
    @classmethod
    def validate_password(cls, v: str | SecretStr) -> SecretStr:
        """Ensure password is wrapped in SecretStr."""
        if isinstance(v, SecretStr):
            return v
        return SecretStr(v) if v else SecretStr("")

    @model_validator(mode="after")
    def parse_module_lists(self) -> "Settings":
        """Parse comma-separated module lists after initialization."""
        if self.blocked_modules:
            self._blocked_modules_list = [
                m.strip() for m in self.blocked_modules.split(",") if m.strip()
            ]
        else:
            self._blocked_modules_list = []

        if self.allowed_modules:
            self._allowed_modules_list = [
                m.strip() for m in self.allowed_modules.split(",") if m.strip()
            ]
        else:
            self._allowed_modules_list = []

        return self

    @property
    def msf_url(self) -> str:
        """Construct full Metasploit RPC URL."""
        scheme = "https" if self.msf_ssl else "http"
        return f"{scheme}://{self.msf_host}:{self.msf_port}{self.msf_uri}"

    def is_module_allowed(self, module_path: str) -> bool:
        """Check if a module is allowed based on whitelist/blacklist."""
        # Check blacklist first
        for blocked in self._blocked_modules_list:
            if module_path.startswith(blocked) or blocked in module_path:
                return False

        # Check whitelist if configured
        if self._allowed_modules_list:
            for allowed in self._allowed_modules_list:
                if module_path.startswith(allowed) or allowed in module_path:
                    return True
            return False

        return True


def get_settings() -> Settings:
    """Get application settings singleton."""
    return Settings()
