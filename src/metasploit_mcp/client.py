"""
Metasploit RPC Client - Async client for Metasploit Framework RPC API.

This module provides a robust, async-compatible client for interacting with
Metasploit's MSGRPC interface, supporting all major API methods.
"""

from __future__ import annotations

import asyncio
import logging
import ssl
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, AsyncGenerator, Optional

import httpx
import msgpack
from asyncio_throttle import Throttler

from metasploit_mcp.config import Settings

logger = logging.getLogger(__name__)


class MsfRpcMethod(str, Enum):
    """Metasploit RPC API methods."""
    # Authentication
    AUTH_LOGIN = "auth.login"
    AUTH_LOGOUT = "auth.logout"
    AUTH_TOKEN_LIST = "auth.token_list"
    AUTH_TOKEN_ADD = "auth.token_add"
    AUTH_TOKEN_REMOVE = "auth.token_remove"
    AUTH_TOKEN_GENERATE = "auth.token_generate"

    # Core
    CORE_VERSION = "core.version"
    CORE_STOP = "core.stop"
    CORE_SETG = "core.setg"
    CORE_UNSETG = "core.unsetg"
    CORE_GETG = "core.getg"
    CORE_SAVE = "core.save"
    CORE_RELOAD_MODULES = "core.reload_modules"
    CORE_MODULE_STATS = "core.module_stats"
    CORE_ADD_MODULE_PATH = "core.add_module_path"
    CORE_THREAD_LIST = "core.thread_list"
    CORE_THREAD_KILL = "core.thread_kill"

    # Console
    CONSOLE_CREATE = "console.create"
    CONSOLE_DESTROY = "console.destroy"
    CONSOLE_LIST = "console.list"
    CONSOLE_READ = "console.read"
    CONSOLE_WRITE = "console.write"
    CONSOLE_TABS = "console.tabs"
    CONSOLE_SESSION_KILL = "console.session_kill"
    CONSOLE_SESSION_DETACH = "console.session_detach"

    # Module
    MODULE_EXPLOITS = "module.exploits"
    MODULE_AUXILIARY = "module.auxiliary"
    MODULE_POST = "module.post"
    MODULE_PAYLOADS = "module.payloads"
    MODULE_ENCODERS = "module.encoders"
    MODULE_NOPS = "module.nops"
    MODULE_EVASION = "module.evasion"
    MODULE_INFO = "module.info"
    MODULE_OPTIONS = "module.options"
    MODULE_COMPATIBLE_PAYLOADS = "module.compatible_payloads"
    MODULE_COMPATIBLE_SESSIONS = "module.compatible_sessions"
    MODULE_TARGET_COMPATIBLE_PAYLOADS = "module.target_compatible_payloads"
    MODULE_EXECUTE = "module.execute"
    MODULE_ENCODE = "module.encode"
    MODULE_SEARCH = "module.search"
    MODULE_RUNNING_STATS = "module.running_stats"
    MODULE_CHECK = "module.check"
    MODULE_RESULTS = "module.results"

    # Plugin
    PLUGIN_LOAD = "plugin.load"
    PLUGIN_UNLOAD = "plugin.unload"
    PLUGIN_LOADED = "plugin.loaded"

    # Job
    JOB_LIST = "job.list"
    JOB_INFO = "job.info"
    JOB_STOP = "job.stop"

    # Session
    SESSION_LIST = "session.list"
    SESSION_STOP = "session.stop"
    SESSION_SHELL_READ = "session.shell_read"
    SESSION_SHELL_WRITE = "session.shell_write"
    SESSION_SHELL_UPGRADE = "session.shell_upgrade"
    SESSION_METERPRETER_READ = "session.meterpreter_read"
    SESSION_METERPRETER_WRITE = "session.meterpreter_write"
    SESSION_METERPRETER_RUN_SINGLE = "session.meterpreter_run_single"
    SESSION_METERPRETER_SCRIPT = "session.meterpreter_script"
    SESSION_METERPRETER_DETACH = "session.meterpreter_session_detach"
    SESSION_METERPRETER_KILL = "session.meterpreter_session_kill"
    SESSION_METERPRETER_TABS = "session.meterpreter_tabs"
    SESSION_METERPRETER_DIR_SEP = "session.meterpreter_directory_separator"
    SESSION_COMPATIBLE_MODULES = "session.compatible_modules"
    SESSION_RING_READ = "session.ring_read"
    SESSION_RING_PUT = "session.ring_put"
    SESSION_RING_LAST = "session.ring_last"
    SESSION_RING_CLEAR = "session.ring_clear"

    # Database
    DB_STATUS = "db.status"
    DB_CONNECT = "db.connect"
    DB_DISCONNECT = "db.disconnect"
    DB_HOSTS = "db.hosts"
    DB_SERVICES = "db.services"
    DB_VULNS = "db.vulns"
    DB_WORKSPACES = "db.workspaces"
    DB_CURRENT_WORKSPACE = "db.current_workspace"
    DB_SET_WORKSPACE = "db.set_workspace"
    DB_ADD_WORKSPACE = "db.add_workspace"
    DB_DEL_WORKSPACE = "db.del_workspace"
    DB_GET_HOST = "db.get_host"
    DB_REPORT_HOST = "db.report_host"
    DB_DEL_HOST = "db.del_host"
    DB_GET_SERVICE = "db.get_service"
    DB_REPORT_SERVICE = "db.report_service"
    DB_DEL_SERVICE = "db.del_service"
    DB_GET_NOTE = "db.get_note"
    DB_NOTES = "db.notes"
    DB_REPORT_NOTE = "db.report_note"
    DB_DEL_NOTE = "db.del_note"
    DB_GET_REF = "db.get_ref"
    DB_GET_VULN = "db.get_vuln"
    DB_REPORT_VULN = "db.report_vuln"
    DB_DEL_VULN = "db.del_vuln"
    DB_CREDS = "db.creds"
    DB_LOOTS = "db.loots"
    DB_REPORT_LOOT = "db.report_loot"
    DB_IMPORT_DATA = "db.import_data"
    DB_EXPORT_DATA = "db.export_data"
    DB_EVENTS = "db.events"
    DB_ANALYZE_HOST = "db.analyze_host"


class MsfRpcError(Exception):
    """Base exception for Metasploit RPC errors."""

    def __init__(self, message: str, code: int = 0, details: dict[str, Any] | None = None):
        self.message = message
        self.code = code
        self.details = details or {}
        super().__init__(message)


class MsfAuthError(MsfRpcError):
    """Authentication error."""
    pass


class MsfConnectionError(MsfRpcError):
    """Connection error."""
    pass


class MsfModuleError(MsfRpcError):
    """Module execution error."""
    pass


@dataclass
class MsfSession:
    """Represents an active Metasploit session."""
    id: int
    type: str
    tunnel_local: str
    tunnel_peer: str
    via_exploit: str
    via_payload: str
    desc: str
    info: str
    workspace: str
    session_host: str
    session_port: int
    target_host: str
    username: str
    uuid: str
    exploit_uuid: str
    routes: list[str]
    arch: str
    platform: str
    created_at: datetime = field(default_factory=datetime.now)

    @classmethod
    def from_dict(cls, session_id: int, data: dict[str, Any]) -> MsfSession:
        """Create session from RPC response data."""
        return cls(
            id=session_id,
            type=data.get("type", "unknown"),
            tunnel_local=data.get("tunnel_local", ""),
            tunnel_peer=data.get("tunnel_peer", ""),
            via_exploit=data.get("via_exploit", ""),
            via_payload=data.get("via_payload", ""),
            desc=data.get("desc", ""),
            info=data.get("info", ""),
            workspace=data.get("workspace", "default"),
            session_host=data.get("session_host", ""),
            session_port=data.get("session_port", 0),
            target_host=data.get("target_host", ""),
            username=data.get("username", ""),
            uuid=data.get("uuid", ""),
            exploit_uuid=data.get("exploit_uuid", ""),
            routes=data.get("routes", []),
            arch=data.get("arch", ""),
            platform=data.get("platform", ""),
        )


@dataclass
class MsfModule:
    """Represents a Metasploit module."""
    type: str
    name: str
    fullname: str
    rank: str
    disclosure_date: str
    description: str
    author: list[str]
    references: list[dict[str, str]]
    targets: list[dict[str, Any]]
    options: dict[str, dict[str, Any]]
    privileged: bool
    platform: list[str]
    arch: list[str]


class MsfRpcClient:
    """
    Async Metasploit RPC client with connection pooling and rate limiting.

    This client provides a robust interface to Metasploit's MSGRPC API,
    supporting authentication, session management, module execution,
    and database operations.
    """

    def __init__(self, settings: Settings):
        """Initialize the RPC client with configuration settings."""
        self.settings = settings
        self._token: str | None = settings.msf_token
        self._client: httpx.AsyncClient | None = None
        self._throttler: Throttler | None = None
        self._connected = False
        self._lock = asyncio.Lock()

    @property
    def is_connected(self) -> bool:
        """Check if client is connected and authenticated."""
        return self._connected and self._token is not None

    async def _get_client(self) -> httpx.AsyncClient:
        """Get or create HTTP client."""
        if self._client is None:
            ssl_context = None
            if self.settings.msf_ssl:
                ssl_context = ssl.create_default_context()
                if not self.settings.msf_ssl_verify:
                    ssl_context.check_hostname = False
                    ssl_context.verify_mode = ssl.CERT_NONE

            self._client = httpx.AsyncClient(
                timeout=httpx.Timeout(
                    connect=self.settings.connection_timeout,
                    read=self.settings.request_timeout,
                    write=self.settings.request_timeout,
                    pool=self.settings.connection_timeout,
                ),
                verify=ssl_context if self.settings.msf_ssl else True,
                headers={"Content-Type": "binary/message-pack"},
            )

        if self.settings.rate_limit_enabled and self._throttler is None:
            self._throttler = Throttler(
                rate_limit=self.settings.rate_limit_calls,
                period=self.settings.rate_limit_period,
            )

        return self._client

    async def _call(
        self,
        method: MsfRpcMethod | str,
        *args: Any,
        retry: bool = True,
    ) -> dict[str, Any]:
        """
        Make an RPC call to Metasploit.

        Args:
            method: RPC method to call
            *args: Method arguments
            retry: Whether to retry on failure

        Returns:
            Response data as dictionary

        Raises:
            MsfAuthError: Authentication failed
            MsfConnectionError: Connection failed
            MsfRpcError: General RPC error
        """
        method_str = method.value if isinstance(method, MsfRpcMethod) else method
        client = await self._get_client()

        # Build request payload
        if method_str == MsfRpcMethod.AUTH_LOGIN.value:
            payload = [method_str, *args]
        elif self._token:
            payload = [method_str, self._token, *args]
        else:
            raise MsfAuthError("Not authenticated - call connect() first")

        encoded = msgpack.packb(payload, use_bin_type=True)

        # Apply rate limiting
        if self._throttler:
            async with self._throttler:
                return await self._execute_request(client, encoded, method_str, retry)
        else:
            return await self._execute_request(client, encoded, method_str, retry)

    async def _execute_request(
        self,
        client: httpx.AsyncClient,
        payload: bytes,
        method: str,
        retry: bool,
    ) -> dict[str, Any]:
        """Execute HTTP request with retry logic."""
        last_error: Exception | None = None
        max_attempts = self.settings.max_retries + 1 if retry else 1

        for attempt in range(max_attempts):
            try:
                response = await client.post(
                    self.settings.msf_url,
                    content=payload,
                )
                response.raise_for_status()

                result = msgpack.unpackb(response.content, raw=False)

                # Check for RPC errors
                if isinstance(result, dict):
                    if "error" in result:
                        error_msg = result.get("error_message", str(result["error"]))
                        error_code = result.get("error_code", 0)

                        if "authentication" in error_msg.lower() or error_code == 401:
                            raise MsfAuthError(error_msg, error_code)
                        raise MsfRpcError(error_msg, error_code, result)

                return result if isinstance(result, dict) else {"result": result}

            except httpx.ConnectError as e:
                last_error = MsfConnectionError(f"Connection failed: {e}")
                logger.warning(f"Connection attempt {attempt + 1} failed: {e}")
            except httpx.TimeoutException as e:
                last_error = MsfConnectionError(f"Request timeout: {e}")
                logger.warning(f"Request timeout on attempt {attempt + 1}: {e}")
            except MsfAuthError:
                raise
            except Exception as e:
                last_error = MsfRpcError(f"RPC call failed: {e}")
                logger.warning(f"RPC call failed on attempt {attempt + 1}: {e}")

            if attempt < max_attempts - 1:
                await asyncio.sleep(self.settings.retry_delay * (attempt + 1))

        raise last_error or MsfConnectionError("Unknown connection error")

    async def connect(self) -> dict[str, Any]:
        """
        Connect and authenticate with Metasploit RPC.

        Returns:
            Authentication result with token

        Raises:
            MsfAuthError: Authentication failed
            MsfConnectionError: Connection failed
        """
        async with self._lock:
            if self._connected and self._token:
                return {"result": "success", "token": self._token}

            password = self.settings.msf_password.get_secret_value()
            if not password:
                raise MsfAuthError("No password configured")

            # Temporarily set token to None for login
            saved_token = self._token
            self._token = "temp"  # Needed to pass the check in _call

            try:
                # Build login request manually
                client = await self._get_client()
                payload = msgpack.packb(
                    [MsfRpcMethod.AUTH_LOGIN.value, self.settings.msf_username, password],
                    use_bin_type=True,
                )
                response = await client.post(self.settings.msf_url, content=payload)
                response.raise_for_status()
                result = msgpack.unpackb(response.content, raw=False)

                if isinstance(result, dict) and "token" in result:
                    self._token = result["token"]
                    self._connected = True
                    logger.info("Successfully authenticated with Metasploit RPC")
                    return result
                else:
                    raise MsfAuthError("Authentication failed - no token received")

            except Exception as e:
                self._token = saved_token
                self._connected = False
                if isinstance(e, MsfAuthError):
                    raise
                raise MsfAuthError(f"Authentication failed: {e}")

    async def disconnect(self) -> None:
        """Disconnect from Metasploit RPC."""
        async with self._lock:
            if self._token and self._connected:
                try:
                    await self._call(MsfRpcMethod.AUTH_LOGOUT, retry=False)
                except Exception as e:
                    logger.warning(f"Error during logout: {e}")

            self._token = None
            self._connected = False

            if self._client:
                await self._client.aclose()
                self._client = None

    @asynccontextmanager
    async def session(self) -> AsyncGenerator[MsfRpcClient, None]:
        """Context manager for RPC session."""
        await self.connect()
        try:
            yield self
        finally:
            await self.disconnect()

    # ==========================================================================
    # Core Methods
    # ==========================================================================

    async def get_version(self) -> dict[str, Any]:
        """Get Metasploit version information."""
        return await self._call(MsfRpcMethod.CORE_VERSION)

    async def get_module_stats(self) -> dict[str, Any]:
        """Get module statistics."""
        return await self._call(MsfRpcMethod.CORE_MODULE_STATS)

    async def reload_modules(self) -> dict[str, Any]:
        """Reload all modules."""
        return await self._call(MsfRpcMethod.CORE_RELOAD_MODULES)

    async def set_global(self, key: str, value: str) -> dict[str, Any]:
        """Set a global variable."""
        return await self._call(MsfRpcMethod.CORE_SETG, key, value)

    async def get_global(self, key: str) -> dict[str, Any]:
        """Get a global variable."""
        return await self._call(MsfRpcMethod.CORE_GETG, key)

    async def list_threads(self) -> dict[str, Any]:
        """List active threads."""
        return await self._call(MsfRpcMethod.CORE_THREAD_LIST)

    async def kill_thread(self, thread_id: int) -> dict[str, Any]:
        """Kill a specific thread."""
        return await self._call(MsfRpcMethod.CORE_THREAD_KILL, thread_id)

    # ==========================================================================
    # Console Methods
    # ==========================================================================

    async def console_create(self) -> dict[str, Any]:
        """Create a new console."""
        return await self._call(MsfRpcMethod.CONSOLE_CREATE)

    async def console_destroy(self, console_id: str) -> dict[str, Any]:
        """Destroy a console."""
        return await self._call(MsfRpcMethod.CONSOLE_DESTROY, console_id)

    async def console_list(self) -> dict[str, Any]:
        """List active consoles."""
        return await self._call(MsfRpcMethod.CONSOLE_LIST)

    async def console_read(self, console_id: str) -> dict[str, Any]:
        """Read console output."""
        return await self._call(MsfRpcMethod.CONSOLE_READ, console_id)

    async def console_write(self, console_id: str, data: str) -> dict[str, Any]:
        """Write to console."""
        return await self._call(MsfRpcMethod.CONSOLE_WRITE, console_id, data)

    # ==========================================================================
    # Module Methods
    # ==========================================================================

    async def list_exploits(self) -> dict[str, Any]:
        """List all exploit modules."""
        return await self._call(MsfRpcMethod.MODULE_EXPLOITS)

    async def list_auxiliary(self) -> dict[str, Any]:
        """List all auxiliary modules."""
        return await self._call(MsfRpcMethod.MODULE_AUXILIARY)

    async def list_post(self) -> dict[str, Any]:
        """List all post-exploitation modules."""
        return await self._call(MsfRpcMethod.MODULE_POST)

    async def list_payloads(self) -> dict[str, Any]:
        """List all payload modules."""
        return await self._call(MsfRpcMethod.MODULE_PAYLOADS)

    async def list_encoders(self) -> dict[str, Any]:
        """List all encoder modules."""
        return await self._call(MsfRpcMethod.MODULE_ENCODERS)

    async def list_nops(self) -> dict[str, Any]:
        """List all NOP modules."""
        return await self._call(MsfRpcMethod.MODULE_NOPS)

    async def list_evasion(self) -> dict[str, Any]:
        """List all evasion modules."""
        return await self._call(MsfRpcMethod.MODULE_EVASION)

    async def get_module_info(self, module_type: str, module_name: str) -> dict[str, Any]:
        """Get detailed information about a module."""
        return await self._call(MsfRpcMethod.MODULE_INFO, module_type, module_name)

    async def get_module_options(self, module_type: str, module_name: str) -> dict[str, Any]:
        """Get module options."""
        return await self._call(MsfRpcMethod.MODULE_OPTIONS, module_type, module_name)

    async def get_compatible_payloads(self, module_name: str) -> dict[str, Any]:
        """Get compatible payloads for an exploit."""
        return await self._call(MsfRpcMethod.MODULE_COMPATIBLE_PAYLOADS, module_name)

    async def search_modules(self, query: str) -> dict[str, Any]:
        """Search for modules."""
        return await self._call(MsfRpcMethod.MODULE_SEARCH, query)

    async def execute_module(
        self,
        module_type: str,
        module_name: str,
        options: dict[str, Any],
    ) -> dict[str, Any]:
        """
        Execute a module.

        Args:
            module_type: Type of module (exploit, auxiliary, post, etc.)
            module_name: Full module name
            options: Module options dictionary

        Returns:
            Execution result
        """
        if not self.settings.is_module_allowed(module_name):
            raise MsfModuleError(f"Module {module_name} is not allowed by configuration")

        return await self._call(MsfRpcMethod.MODULE_EXECUTE, module_type, module_name, options)

    async def check_module(
        self,
        module_type: str,
        module_name: str,
        options: dict[str, Any],
    ) -> dict[str, Any]:
        """Check if a target is vulnerable without exploitation."""
        return await self._call(MsfRpcMethod.MODULE_CHECK, module_type, module_name, options)

    async def encode_payload(
        self,
        data: str,
        encoder: str,
        options: dict[str, Any],
    ) -> dict[str, Any]:
        """Encode payload data."""
        return await self._call(MsfRpcMethod.MODULE_ENCODE, data, encoder, options)

    async def get_running_stats(self) -> dict[str, Any]:
        """Get statistics about running modules."""
        return await self._call(MsfRpcMethod.MODULE_RUNNING_STATS)

    # ==========================================================================
    # Job Methods
    # ==========================================================================

    async def list_jobs(self) -> dict[str, Any]:
        """List active jobs."""
        return await self._call(MsfRpcMethod.JOB_LIST)

    async def get_job_info(self, job_id: str) -> dict[str, Any]:
        """Get information about a job."""
        return await self._call(MsfRpcMethod.JOB_INFO, job_id)

    async def stop_job(self, job_id: str) -> dict[str, Any]:
        """Stop a running job."""
        return await self._call(MsfRpcMethod.JOB_STOP, job_id)

    # ==========================================================================
    # Session Methods
    # ==========================================================================

    async def list_sessions(self) -> dict[str, MsfSession]:
        """List all active sessions."""
        result = await self._call(MsfRpcMethod.SESSION_LIST)
        sessions = {}
        for session_id, data in result.items():
            if isinstance(session_id, (int, str)) and isinstance(data, dict):
                sid = int(session_id)
                sessions[sid] = MsfSession.from_dict(sid, data)
        return sessions

    async def stop_session(self, session_id: int) -> dict[str, Any]:
        """Stop/kill a session."""
        return await self._call(MsfRpcMethod.SESSION_STOP, str(session_id))

    async def shell_read(self, session_id: int, read_ptr: int = 0) -> dict[str, Any]:
        """Read from a shell session."""
        return await self._call(MsfRpcMethod.SESSION_SHELL_READ, str(session_id), read_ptr)

    async def shell_write(self, session_id: int, data: str) -> dict[str, Any]:
        """Write to a shell session."""
        return await self._call(MsfRpcMethod.SESSION_SHELL_WRITE, str(session_id), data)

    async def shell_upgrade(
        self,
        session_id: int,
        lhost: str,
        lport: int,
    ) -> dict[str, Any]:
        """Upgrade a shell to Meterpreter."""
        return await self._call(
            MsfRpcMethod.SESSION_SHELL_UPGRADE,
            str(session_id),
            lhost,
            lport,
        )

    async def meterpreter_read(self, session_id: int) -> dict[str, Any]:
        """Read from a Meterpreter session."""
        return await self._call(MsfRpcMethod.SESSION_METERPRETER_READ, str(session_id))

    async def meterpreter_write(self, session_id: int, data: str) -> dict[str, Any]:
        """Write to a Meterpreter session."""
        return await self._call(MsfRpcMethod.SESSION_METERPRETER_WRITE, str(session_id), data)

    async def meterpreter_run_single(self, session_id: int, command: str) -> dict[str, Any]:
        """Run a single Meterpreter command."""
        return await self._call(
            MsfRpcMethod.SESSION_METERPRETER_RUN_SINGLE,
            str(session_id),
            command,
        )

    async def meterpreter_script(self, session_id: int, script: str) -> dict[str, Any]:
        """Run a Meterpreter script."""
        return await self._call(MsfRpcMethod.SESSION_METERPRETER_SCRIPT, str(session_id), script)

    async def get_compatible_post_modules(self, session_id: int) -> dict[str, Any]:
        """Get post modules compatible with a session."""
        return await self._call(MsfRpcMethod.SESSION_COMPATIBLE_MODULES, str(session_id))

    # ==========================================================================
    # Database Methods
    # ==========================================================================

    async def db_status(self) -> dict[str, Any]:
        """Get database status."""
        return await self._call(MsfRpcMethod.DB_STATUS)

    async def db_connect(self, connection_string: str) -> dict[str, Any]:
        """Connect to database."""
        return await self._call(MsfRpcMethod.DB_CONNECT, connection_string)

    async def db_disconnect(self) -> dict[str, Any]:
        """Disconnect from database."""
        return await self._call(MsfRpcMethod.DB_DISCONNECT)

    async def list_workspaces(self) -> dict[str, Any]:
        """List all workspaces."""
        return await self._call(MsfRpcMethod.DB_WORKSPACES)

    async def get_current_workspace(self) -> dict[str, Any]:
        """Get current workspace."""
        return await self._call(MsfRpcMethod.DB_CURRENT_WORKSPACE)

    async def set_workspace(self, workspace: str) -> dict[str, Any]:
        """Set current workspace."""
        return await self._call(MsfRpcMethod.DB_SET_WORKSPACE, workspace)

    async def add_workspace(self, workspace: str) -> dict[str, Any]:
        """Create a new workspace."""
        return await self._call(MsfRpcMethod.DB_ADD_WORKSPACE, workspace)

    async def delete_workspace(self, workspace: str) -> dict[str, Any]:
        """Delete a workspace."""
        return await self._call(MsfRpcMethod.DB_DEL_WORKSPACE, workspace)

    async def list_hosts(self, options: dict[str, Any] | None = None) -> dict[str, Any]:
        """List hosts in database."""
        return await self._call(MsfRpcMethod.DB_HOSTS, options or {})

    async def get_host(self, address: str) -> dict[str, Any]:
        """Get host information."""
        return await self._call(MsfRpcMethod.DB_GET_HOST, {"address": address})

    async def report_host(self, host_data: dict[str, Any]) -> dict[str, Any]:
        """Report/add a host to database."""
        return await self._call(MsfRpcMethod.DB_REPORT_HOST, host_data)

    async def delete_host(self, addresses: list[str]) -> dict[str, Any]:
        """Delete hosts from database."""
        return await self._call(MsfRpcMethod.DB_DEL_HOST, {"addresses": addresses})

    async def list_services(self, options: dict[str, Any] | None = None) -> dict[str, Any]:
        """List services in database."""
        return await self._call(MsfRpcMethod.DB_SERVICES, options or {})

    async def report_service(self, service_data: dict[str, Any]) -> dict[str, Any]:
        """Report/add a service to database."""
        return await self._call(MsfRpcMethod.DB_REPORT_SERVICE, service_data)

    async def list_vulns(self, options: dict[str, Any] | None = None) -> dict[str, Any]:
        """List vulnerabilities in database."""
        return await self._call(MsfRpcMethod.DB_VULNS, options or {})

    async def report_vuln(self, vuln_data: dict[str, Any]) -> dict[str, Any]:
        """Report a vulnerability to database."""
        return await self._call(MsfRpcMethod.DB_REPORT_VULN, vuln_data)

    async def list_creds(self, options: dict[str, Any] | None = None) -> dict[str, Any]:
        """List credentials in database."""
        return await self._call(MsfRpcMethod.DB_CREDS, options or {})

    async def list_loots(self, options: dict[str, Any] | None = None) -> dict[str, Any]:
        """List loot in database."""
        return await self._call(MsfRpcMethod.DB_LOOTS, options or {})

    async def report_loot(self, loot_data: dict[str, Any]) -> dict[str, Any]:
        """Report loot to database."""
        return await self._call(MsfRpcMethod.DB_REPORT_LOOT, loot_data)

    async def list_notes(self, options: dict[str, Any] | None = None) -> dict[str, Any]:
        """List notes in database."""
        return await self._call(MsfRpcMethod.DB_NOTES, options or {})

    async def import_data(self, data: str, data_type: str = "xml") -> dict[str, Any]:
        """Import scan data into database."""
        return await self._call(MsfRpcMethod.DB_IMPORT_DATA, {"data": data, "type": data_type})

    async def export_data(
        self,
        format_type: str = "xml",
        path: str | None = None,
    ) -> dict[str, Any]:
        """Export database data."""
        options = {"format": format_type}
        if path:
            options["path"] = path
        return await self._call(MsfRpcMethod.DB_EXPORT_DATA, options)

    async def analyze_host(self, address: str) -> dict[str, Any]:
        """Analyze a host for vulnerabilities."""
        return await self._call(MsfRpcMethod.DB_ANALYZE_HOST, {"address": address})

    # ==========================================================================
    # Plugin Methods
    # ==========================================================================

    async def load_plugin(self, plugin_name: str, options: dict[str, Any] | None = None) -> dict[str, Any]:
        """Load a plugin."""
        return await self._call(MsfRpcMethod.PLUGIN_LOAD, plugin_name, options or {})

    async def unload_plugin(self, plugin_name: str) -> dict[str, Any]:
        """Unload a plugin."""
        return await self._call(MsfRpcMethod.PLUGIN_UNLOAD, plugin_name)

    async def list_plugins(self) -> dict[str, Any]:
        """List loaded plugins."""
        return await self._call(MsfRpcMethod.PLUGIN_LOADED)
