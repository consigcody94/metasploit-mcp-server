"""
Metasploit MCP Server - Main server implementation.

This module implements the Model Context Protocol server that exposes
Metasploit Framework capabilities to AI agents in a secure, controlled manner.
"""

from __future__ import annotations

import asyncio
import json
import logging
from collections.abc import Sequence
from datetime import datetime
from typing import Any

from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import (
    EmbeddedResource,
    GetPromptResult,
    ImageContent,
    Prompt,
    PromptArgument,
    PromptMessage,
    Resource,
    TextContent,
    Tool,
)
from pydantic import AnyUrl

from metasploit_mcp.client import MsfRpcClient, MsfRpcError
from metasploit_mcp.config import Settings, get_settings

logger = logging.getLogger(__name__)


class MetasploitMCPServer:
    """
    Model Context Protocol server for Metasploit Framework.

    Provides AI agents with controlled access to:
    - Module discovery and information
    - Exploit execution (with safety controls)
    - Session management
    - Database operations
    - Payload generation
    """

    def __init__(self, settings: Settings | None = None):
        """Initialize the MCP server."""
        self.settings = settings or get_settings()
        self.client = MsfRpcClient(self.settings)
        self.server = Server(self.settings.server_name)
        self._setup_handlers()
        self._audit_log: list[dict[str, Any]] = []

    def _audit(self, action: str, details: dict[str, Any]) -> None:
        """Log an audit entry."""
        if self.settings.audit_logging:
            entry = {
                "timestamp": datetime.utcnow().isoformat(),
                "action": action,
                "details": details,
            }
            self._audit_log.append(entry)
            logger.info(f"AUDIT: {action} - {json.dumps(details)}")

    def _setup_handlers(self) -> None:
        """Set up MCP protocol handlers."""

        @self.server.list_tools()
        async def list_tools() -> list[Tool]:
            """List all available tools."""
            tools = []

            # Core tools
            tools.append(
                Tool(
                    name="msf_version",
                    description="Get Metasploit Framework version and system information",
                    inputSchema={
                        "type": "object",
                        "properties": {},
                        "required": [],
                    },
                )
            )

            tools.append(
                Tool(
                    name="msf_module_stats",
                    description="Get statistics about available modules (exploits, auxiliary, post, payloads, etc.)",
                    inputSchema={
                        "type": "object",
                        "properties": {},
                        "required": [],
                    },
                )
            )

            # Module discovery tools
            tools.append(
                Tool(
                    name="msf_search",
                    description="Search for Metasploit modules by keyword, CVE, platform, or other criteria",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "query": {
                                "type": "string",
                                "description": "Search query (e.g., 'cve:2021-44228', 'type:exploit platform:windows', 'apache')",
                            },
                        },
                        "required": ["query"],
                    },
                )
            )

            tools.append(
                Tool(
                    name="msf_module_info",
                    description="Get detailed information about a specific module",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "module_type": {
                                "type": "string",
                                "enum": [
                                    "exploit",
                                    "auxiliary",
                                    "post",
                                    "payload",
                                    "encoder",
                                    "nop",
                                    "evasion",
                                ],
                                "description": "Type of module",
                            },
                            "module_name": {
                                "type": "string",
                                "description": "Full module name (e.g., 'windows/smb/ms17_010_eternalblue')",
                            },
                        },
                        "required": ["module_type", "module_name"],
                    },
                )
            )

            tools.append(
                Tool(
                    name="msf_module_options",
                    description="Get configurable options for a module",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "module_type": {
                                "type": "string",
                                "enum": [
                                    "exploit",
                                    "auxiliary",
                                    "post",
                                    "payload",
                                    "encoder",
                                    "nop",
                                    "evasion",
                                ],
                                "description": "Type of module",
                            },
                            "module_name": {
                                "type": "string",
                                "description": "Full module name",
                            },
                        },
                        "required": ["module_type", "module_name"],
                    },
                )
            )

            tools.append(
                Tool(
                    name="msf_compatible_payloads",
                    description="Get list of payloads compatible with an exploit",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "exploit_name": {
                                "type": "string",
                                "description": "Full exploit name",
                            },
                        },
                        "required": ["exploit_name"],
                    },
                )
            )

            # Module listing tools
            for mod_type in [
                "exploits",
                "auxiliary",
                "post",
                "payloads",
                "encoders",
                "nops",
                "evasion",
            ]:
                tools.append(
                    Tool(
                        name=f"msf_list_{mod_type}",
                        description=f"List all available {mod_type} modules",
                        inputSchema={
                            "type": "object",
                            "properties": {},
                            "required": [],
                        },
                    )
                )

            # Exploit execution tools
            if self.settings.enable_exploit_tools:
                tools.append(
                    Tool(
                        name="msf_check",
                        description="Check if a target is vulnerable without exploitation (safe reconnaissance)",
                        inputSchema={
                            "type": "object",
                            "properties": {
                                "module_type": {
                                    "type": "string",
                                    "enum": ["exploit", "auxiliary"],
                                    "description": "Type of module",
                                },
                                "module_name": {
                                    "type": "string",
                                    "description": "Full module name",
                                },
                                "options": {
                                    "type": "object",
                                    "description": "Module options (RHOSTS, RPORT, etc.)",
                                    "additionalProperties": True,
                                },
                            },
                            "required": ["module_type", "module_name", "options"],
                        },
                    )
                )

                tools.append(
                    Tool(
                        name="msf_execute",
                        description="Execute a Metasploit module (exploit, auxiliary, or post). REQUIRES AUTHORIZATION.",
                        inputSchema={
                            "type": "object",
                            "properties": {
                                "module_type": {
                                    "type": "string",
                                    "enum": ["exploit", "auxiliary", "post"],
                                    "description": "Type of module to execute",
                                },
                                "module_name": {
                                    "type": "string",
                                    "description": "Full module name",
                                },
                                "options": {
                                    "type": "object",
                                    "description": "Module options including RHOSTS, RPORT, PAYLOAD, etc.",
                                    "additionalProperties": True,
                                },
                            },
                            "required": ["module_type", "module_name", "options"],
                        },
                    )
                )

            # Session management tools
            if self.settings.enable_session_tools:
                tools.append(
                    Tool(
                        name="msf_sessions_list",
                        description="List all active sessions (shells, meterpreter)",
                        inputSchema={
                            "type": "object",
                            "properties": {},
                            "required": [],
                        },
                    )
                )

                tools.append(
                    Tool(
                        name="msf_session_info",
                        description="Get detailed information about a specific session",
                        inputSchema={
                            "type": "object",
                            "properties": {
                                "session_id": {
                                    "type": "integer",
                                    "description": "Session ID",
                                },
                            },
                            "required": ["session_id"],
                        },
                    )
                )

                tools.append(
                    Tool(
                        name="msf_session_run",
                        description="Run a command in a session (shell or meterpreter)",
                        inputSchema={
                            "type": "object",
                            "properties": {
                                "session_id": {
                                    "type": "integer",
                                    "description": "Session ID",
                                },
                                "command": {
                                    "type": "string",
                                    "description": "Command to execute",
                                },
                            },
                            "required": ["session_id", "command"],
                        },
                    )
                )

                tools.append(
                    Tool(
                        name="msf_session_stop",
                        description="Terminate a session",
                        inputSchema={
                            "type": "object",
                            "properties": {
                                "session_id": {
                                    "type": "integer",
                                    "description": "Session ID to terminate",
                                },
                            },
                            "required": ["session_id"],
                        },
                    )
                )

                tools.append(
                    Tool(
                        name="msf_session_upgrade",
                        description="Upgrade a shell session to Meterpreter",
                        inputSchema={
                            "type": "object",
                            "properties": {
                                "session_id": {
                                    "type": "integer",
                                    "description": "Shell session ID to upgrade",
                                },
                                "lhost": {
                                    "type": "string",
                                    "description": "Local host for Meterpreter connection",
                                },
                                "lport": {
                                    "type": "integer",
                                    "description": "Local port for Meterpreter connection",
                                },
                            },
                            "required": ["session_id", "lhost", "lport"],
                        },
                    )
                )

            # Post-exploitation tools
            if self.settings.enable_post_tools:
                tools.append(
                    Tool(
                        name="msf_session_compatible_modules",
                        description="Get post-exploitation modules compatible with a session",
                        inputSchema={
                            "type": "object",
                            "properties": {
                                "session_id": {
                                    "type": "integer",
                                    "description": "Session ID",
                                },
                            },
                            "required": ["session_id"],
                        },
                    )
                )

            # Payload generation tools
            if self.settings.enable_payload_tools:
                tools.append(
                    Tool(
                        name="msf_encode_payload",
                        description="Encode a payload with specified encoder",
                        inputSchema={
                            "type": "object",
                            "properties": {
                                "data": {
                                    "type": "string",
                                    "description": "Raw payload data (base64 encoded)",
                                },
                                "encoder": {
                                    "type": "string",
                                    "description": "Encoder module name",
                                },
                                "options": {
                                    "type": "object",
                                    "description": "Encoder options",
                                    "additionalProperties": True,
                                },
                            },
                            "required": ["data", "encoder"],
                        },
                    )
                )

            # Database tools
            if self.settings.enable_db_tools:
                tools.append(
                    Tool(
                        name="msf_db_status",
                        description="Get database connection status",
                        inputSchema={
                            "type": "object",
                            "properties": {},
                            "required": [],
                        },
                    )
                )

                tools.append(
                    Tool(
                        name="msf_workspaces",
                        description="List or manage workspaces",
                        inputSchema={
                            "type": "object",
                            "properties": {
                                "action": {
                                    "type": "string",
                                    "enum": ["list", "current", "set", "add", "delete"],
                                    "description": "Action to perform",
                                },
                                "workspace": {
                                    "type": "string",
                                    "description": "Workspace name (for set/add/delete)",
                                },
                            },
                            "required": ["action"],
                        },
                    )
                )

                tools.append(
                    Tool(
                        name="msf_hosts",
                        description="List or manage hosts in database",
                        inputSchema={
                            "type": "object",
                            "properties": {
                                "action": {
                                    "type": "string",
                                    "enum": ["list", "get", "add", "delete"],
                                    "description": "Action to perform",
                                },
                                "address": {
                                    "type": "string",
                                    "description": "Host address",
                                },
                                "host_data": {
                                    "type": "object",
                                    "description": "Host data for add action",
                                    "additionalProperties": True,
                                },
                            },
                            "required": ["action"],
                        },
                    )
                )

                tools.append(
                    Tool(
                        name="msf_services",
                        description="List services in database",
                        inputSchema={
                            "type": "object",
                            "properties": {
                                "host": {
                                    "type": "string",
                                    "description": "Filter by host address",
                                },
                                "port": {
                                    "type": "integer",
                                    "description": "Filter by port",
                                },
                                "proto": {
                                    "type": "string",
                                    "enum": ["tcp", "udp"],
                                    "description": "Filter by protocol",
                                },
                            },
                            "required": [],
                        },
                    )
                )

                tools.append(
                    Tool(
                        name="msf_vulns",
                        description="List vulnerabilities in database",
                        inputSchema={
                            "type": "object",
                            "properties": {
                                "host": {
                                    "type": "string",
                                    "description": "Filter by host address",
                                },
                            },
                            "required": [],
                        },
                    )
                )

                tools.append(
                    Tool(
                        name="msf_creds",
                        description="List credentials in database",
                        inputSchema={
                            "type": "object",
                            "properties": {
                                "workspace": {
                                    "type": "string",
                                    "description": "Workspace to query",
                                },
                            },
                            "required": [],
                        },
                    )
                )

                tools.append(
                    Tool(
                        name="msf_loots",
                        description="List captured loot in database",
                        inputSchema={
                            "type": "object",
                            "properties": {
                                "host": {
                                    "type": "string",
                                    "description": "Filter by host",
                                },
                            },
                            "required": [],
                        },
                    )
                )

                tools.append(
                    Tool(
                        name="msf_import_scan",
                        description="Import scan results (Nmap, Nessus, etc.) into database",
                        inputSchema={
                            "type": "object",
                            "properties": {
                                "data": {
                                    "type": "string",
                                    "description": "Scan data (XML format)",
                                },
                                "data_type": {
                                    "type": "string",
                                    "enum": [
                                        "nmap_xml",
                                        "nessus_xml",
                                        "nexpose_simple",
                                        "qualys_scan",
                                    ],
                                    "description": "Type of scan data",
                                },
                            },
                            "required": ["data", "data_type"],
                        },
                    )
                )

            # Job management tools
            tools.append(
                Tool(
                    name="msf_jobs",
                    description="List or manage background jobs",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "action": {
                                "type": "string",
                                "enum": ["list", "info", "stop"],
                                "description": "Action to perform",
                            },
                            "job_id": {
                                "type": "string",
                                "description": "Job ID (for info/stop)",
                            },
                        },
                        "required": ["action"],
                    },
                )
            )

            # Console tools
            tools.append(
                Tool(
                    name="msf_console",
                    description="Interact with Metasploit console",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "action": {
                                "type": "string",
                                "enum": ["create", "list", "destroy", "read", "write"],
                                "description": "Console action",
                            },
                            "console_id": {
                                "type": "string",
                                "description": "Console ID (for destroy/read/write)",
                            },
                            "data": {
                                "type": "string",
                                "description": "Data to write (for write action)",
                            },
                        },
                        "required": ["action"],
                    },
                )
            )

            return tools

        @self.server.call_tool()
        async def call_tool(
            name: str, arguments: dict[str, Any]
        ) -> Sequence[TextContent | ImageContent | EmbeddedResource]:
            """Handle tool calls."""
            self._audit("tool_call", {"tool": name, "arguments": arguments})

            try:
                # Ensure connection
                if not self.client.is_connected:
                    await self.client.connect()

                result = await self._handle_tool(name, arguments)
                return [TextContent(type="text", text=json.dumps(result, indent=2, default=str))]

            except MsfRpcError as e:
                error_response = {
                    "error": True,
                    "message": str(e),
                    "code": e.code,
                    "details": e.details,
                }
                return [TextContent(type="text", text=json.dumps(error_response, indent=2))]
            except Exception as e:
                logger.exception(f"Tool execution error: {e}")
                error_response = {
                    "error": True,
                    "message": f"Unexpected error: {e}",
                }
                return [TextContent(type="text", text=json.dumps(error_response, indent=2))]

        @self.server.list_resources()
        async def list_resources() -> list[Resource]:
            """List available resources."""
            resources = [
                Resource(
                    uri=AnyUrl("msf://modules/exploits"),
                    name="Exploit Modules",
                    description="List of all exploit modules",
                    mimeType="application/json",
                ),
                Resource(
                    uri=AnyUrl("msf://modules/auxiliary"),
                    name="Auxiliary Modules",
                    description="List of all auxiliary modules",
                    mimeType="application/json",
                ),
                Resource(
                    uri=AnyUrl("msf://modules/post"),
                    name="Post Modules",
                    description="List of all post-exploitation modules",
                    mimeType="application/json",
                ),
                Resource(
                    uri=AnyUrl("msf://modules/payloads"),
                    name="Payload Modules",
                    description="List of all payload modules",
                    mimeType="application/json",
                ),
                Resource(
                    uri=AnyUrl("msf://sessions"),
                    name="Active Sessions",
                    description="Currently active sessions",
                    mimeType="application/json",
                ),
                Resource(
                    uri=AnyUrl("msf://jobs"),
                    name="Background Jobs",
                    description="Currently running background jobs",
                    mimeType="application/json",
                ),
                Resource(
                    uri=AnyUrl("msf://db/hosts"),
                    name="Database Hosts",
                    description="Hosts in the database",
                    mimeType="application/json",
                ),
                Resource(
                    uri=AnyUrl("msf://db/services"),
                    name="Database Services",
                    description="Services in the database",
                    mimeType="application/json",
                ),
                Resource(
                    uri=AnyUrl("msf://db/vulns"),
                    name="Database Vulnerabilities",
                    description="Vulnerabilities in the database",
                    mimeType="application/json",
                ),
            ]
            return resources

        @self.server.read_resource()
        async def read_resource(uri: AnyUrl) -> str:
            """Read a resource."""
            uri_str = str(uri)

            if not self.client.is_connected:
                await self.client.connect()

            if uri_str == "msf://modules/exploits":
                result = await self.client.list_exploits()
            elif uri_str == "msf://modules/auxiliary":
                result = await self.client.list_auxiliary()
            elif uri_str == "msf://modules/post":
                result = await self.client.list_post()
            elif uri_str == "msf://modules/payloads":
                result = await self.client.list_payloads()
            elif uri_str == "msf://sessions":
                sessions = await self.client.list_sessions()
                result = {k: v.__dict__ for k, v in sessions.items()}
            elif uri_str == "msf://jobs":
                result = await self.client.list_jobs()
            elif uri_str == "msf://db/hosts":
                result = await self.client.list_hosts()
            elif uri_str == "msf://db/services":
                result = await self.client.list_services()
            elif uri_str == "msf://db/vulns":
                result = await self.client.list_vulns()
            else:
                result = {"error": f"Unknown resource: {uri_str}"}

            return json.dumps(result, indent=2, default=str)

        @self.server.list_prompts()
        async def list_prompts() -> list[Prompt]:
            """List available prompts."""
            return [
                Prompt(
                    name="pentest_recon",
                    description="Reconnaissance workflow for a target",
                    arguments=[
                        PromptArgument(
                            name="target",
                            description="Target IP address or hostname",
                            required=True,
                        ),
                    ],
                ),
                Prompt(
                    name="vuln_assessment",
                    description="Vulnerability assessment workflow",
                    arguments=[
                        PromptArgument(
                            name="target",
                            description="Target IP or range",
                            required=True,
                        ),
                        PromptArgument(
                            name="scope",
                            description="Assessment scope (quick, standard, thorough)",
                            required=False,
                        ),
                    ],
                ),
                Prompt(
                    name="exploit_guide",
                    description="Guide for exploiting a specific vulnerability",
                    arguments=[
                        PromptArgument(
                            name="cve",
                            description="CVE identifier",
                            required=True,
                        ),
                        PromptArgument(
                            name="target",
                            description="Target IP address",
                            required=True,
                        ),
                    ],
                ),
                Prompt(
                    name="post_exploitation",
                    description="Post-exploitation workflow for an active session",
                    arguments=[
                        PromptArgument(
                            name="session_id",
                            description="Active session ID",
                            required=True,
                        ),
                    ],
                ),
            ]

        @self.server.get_prompt()
        async def get_prompt(name: str, arguments: dict[str, str] | None) -> GetPromptResult:
            """Get a specific prompt."""
            args = arguments or {}

            if name == "pentest_recon":
                target = args.get("target", "TARGET")
                return GetPromptResult(
                    description=f"Reconnaissance workflow for {target}",
                    messages=[
                        PromptMessage(
                            role="user",
                            content=TextContent(
                                type="text",
                                text=f"""Perform reconnaissance on target: {target}

1. First, search for relevant auxiliary scanner modules
2. Run port scanning modules to identify open services
3. Identify potential vulnerabilities based on discovered services
4. Document findings in the database

Use the following tools in sequence:
- msf_search to find scanner modules
- msf_execute to run auxiliary/scanner modules
- msf_hosts and msf_services to review findings
- msf_vulns to check for known vulnerabilities

Ensure all actions are authorized and within scope.""",
                            ),
                        ),
                    ],
                )

            elif name == "vuln_assessment":
                target = args.get("target", "TARGET")
                scope = args.get("scope", "standard")
                return GetPromptResult(
                    description=f"Vulnerability assessment for {target} ({scope})",
                    messages=[
                        PromptMessage(
                            role="user",
                            content=TextContent(
                                type="text",
                                text=f"""Perform a {scope} vulnerability assessment on: {target}

Assessment scope: {scope}
- quick: Port scan + basic vuln check
- standard: Full port scan + service enumeration + vuln check
- thorough: All of above + exploit checking (no execution)

Steps:
1. Import any existing scan data if available
2. Run appropriate scanner modules based on scope
3. Check for known vulnerabilities using msf_check (safe mode)
4. Generate a report of findings

Important: Only use msf_check for vulnerability verification, not msf_execute.
All testing must be authorized.""",
                            ),
                        ),
                    ],
                )

            elif name == "exploit_guide":
                cve = args.get("cve", "CVE-XXXX-XXXX")
                target = args.get("target", "TARGET")
                return GetPromptResult(
                    description=f"Exploitation guide for {cve}",
                    messages=[
                        PromptMessage(
                            role="user",
                            content=TextContent(
                                type="text",
                                text=f"""Guide for exploiting {cve} on {target}

1. Search for modules related to {cve}:
   - Use msf_search with query "cve:{cve}"

2. Get module details:
   - Use msf_module_info for the found exploit
   - Use msf_module_options to see required settings

3. Get compatible payloads:
   - Use msf_compatible_payloads

4. Check vulnerability (safe):
   - Use msf_check to verify target is vulnerable

5. If authorized and confirmed vulnerable:
   - Use msf_execute with appropriate options

IMPORTANT: Ensure you have explicit authorization before exploitation.
Document all actions for audit purposes.""",
                            ),
                        ),
                    ],
                )

            elif name == "post_exploitation":
                session_id = args.get("session_id", "1")
                return GetPromptResult(
                    description=f"Post-exploitation for session {session_id}",
                    messages=[
                        PromptMessage(
                            role="user",
                            content=TextContent(
                                type="text",
                                text=f"""Post-exploitation workflow for session {session_id}

1. Verify session is active:
   - Use msf_sessions_list
   - Use msf_session_info for session {session_id}

2. Get compatible post modules:
   - Use msf_session_compatible_modules

3. Common post-exploitation tasks:
   - System information gathering
   - User enumeration
   - Network discovery
   - Credential harvesting (if authorized)
   - Persistence (if authorized)

4. Run specific post modules using msf_execute with:
   - module_type: "post"
   - SESSION option set to {session_id}

5. Document all findings using database tools

IMPORTANT: All post-exploitation must be within authorized scope.
Maintain operational security and document everything.""",
                            ),
                        ),
                    ],
                )

            return GetPromptResult(
                description="Unknown prompt",
                messages=[
                    PromptMessage(
                        role="user",
                        content=TextContent(type="text", text="Unknown prompt requested"),
                    ),
                ],
            )

    async def _handle_tool(self, name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        """Handle individual tool calls."""

        # Core tools
        if name == "msf_version":
            return await self.client.get_version()

        elif name == "msf_module_stats":
            return await self.client.get_module_stats()

        # Module discovery
        elif name == "msf_search":
            return await self.client.search_modules(arguments["query"])

        elif name == "msf_module_info":
            return await self.client.get_module_info(
                arguments["module_type"],
                arguments["module_name"],
            )

        elif name == "msf_module_options":
            return await self.client.get_module_options(
                arguments["module_type"],
                arguments["module_name"],
            )

        elif name == "msf_compatible_payloads":
            return await self.client.get_compatible_payloads(arguments["exploit_name"])

        # Module listing
        elif name == "msf_list_exploits":
            return await self.client.list_exploits()
        elif name == "msf_list_auxiliary":
            return await self.client.list_auxiliary()
        elif name == "msf_list_post":
            return await self.client.list_post()
        elif name == "msf_list_payloads":
            return await self.client.list_payloads()
        elif name == "msf_list_encoders":
            return await self.client.list_encoders()
        elif name == "msf_list_nops":
            return await self.client.list_nops()
        elif name == "msf_list_evasion":
            return await self.client.list_evasion()

        # Exploit execution
        elif name == "msf_check":
            if self.settings.dry_run_mode:
                return {
                    "dry_run": True,
                    "message": "Check would be executed",
                    "arguments": arguments,
                }
            return await self.client.check_module(
                arguments["module_type"],
                arguments["module_name"],
                arguments.get("options", {}),
            )

        elif name == "msf_execute":
            if self.settings.dry_run_mode:
                return {
                    "dry_run": True,
                    "message": "Execution skipped in dry-run mode",
                    "arguments": arguments,
                }

            module_name = arguments["module_name"]
            if not self.settings.is_module_allowed(module_name):
                return {
                    "error": True,
                    "message": f"Module {module_name} is blocked by configuration",
                }

            return await self.client.execute_module(
                arguments["module_type"],
                arguments["module_name"],
                arguments.get("options", {}),
            )

        # Session management
        elif name == "msf_sessions_list":
            sessions = await self.client.list_sessions()
            return {k: v.__dict__ for k, v in sessions.items()}

        elif name == "msf_session_info":
            sessions = await self.client.list_sessions()
            session_id = arguments["session_id"]
            if session_id in sessions:
                return sessions[session_id].__dict__
            return {"error": True, "message": f"Session {session_id} not found"}

        elif name == "msf_session_run":
            session_id = arguments["session_id"]
            command = arguments["command"]
            sessions = await self.client.list_sessions()

            if session_id not in sessions:
                return {"error": True, "message": f"Session {session_id} not found"}

            session = sessions[session_id]
            if session.type == "meterpreter":
                return await self.client.meterpreter_run_single(session_id, command)
            else:
                await self.client.shell_write(session_id, command + "\n")
                await asyncio.sleep(0.5)  # Brief delay for output
                return await self.client.shell_read(session_id)

        elif name == "msf_session_stop":
            return await self.client.stop_session(arguments["session_id"])

        elif name == "msf_session_upgrade":
            return await self.client.shell_upgrade(
                arguments["session_id"],
                arguments["lhost"],
                arguments["lport"],
            )

        elif name == "msf_session_compatible_modules":
            return await self.client.get_compatible_post_modules(arguments["session_id"])

        # Payload tools
        elif name == "msf_encode_payload":
            return await self.client.encode_payload(
                arguments["data"],
                arguments["encoder"],
                arguments.get("options", {}),
            )

        # Database tools
        elif name == "msf_db_status":
            return await self.client.db_status()

        elif name == "msf_workspaces":
            action = arguments["action"]
            if action == "list":
                return await self.client.list_workspaces()
            elif action == "current":
                return await self.client.get_current_workspace()
            elif action == "set":
                return await self.client.set_workspace(arguments["workspace"])
            elif action == "add":
                return await self.client.add_workspace(arguments["workspace"])
            elif action == "delete":
                return await self.client.delete_workspace(arguments["workspace"])

        elif name == "msf_hosts":
            action = arguments["action"]
            if action == "list":
                return await self.client.list_hosts()
            elif action == "get":
                return await self.client.get_host(arguments["address"])
            elif action == "add":
                return await self.client.report_host(arguments.get("host_data", {}))
            elif action == "delete":
                return await self.client.delete_host([arguments["address"]])

        elif name == "msf_services":
            options = {}
            if "host" in arguments:
                options["host"] = arguments["host"]
            if "port" in arguments:
                options["port"] = arguments["port"]
            if "proto" in arguments:
                options["proto"] = arguments["proto"]
            return await self.client.list_services(options)

        elif name == "msf_vulns":
            options = {}
            if "host" in arguments:
                options["host"] = arguments["host"]
            return await self.client.list_vulns(options)

        elif name == "msf_creds":
            return await self.client.list_creds()

        elif name == "msf_loots":
            options = {}
            if "host" in arguments:
                options["host"] = arguments["host"]
            return await self.client.list_loots(options)

        elif name == "msf_import_scan":
            return await self.client.import_data(
                arguments["data"],
                arguments.get("data_type", "nmap_xml"),
            )

        # Job management
        elif name == "msf_jobs":
            action = arguments["action"]
            if action == "list":
                return await self.client.list_jobs()
            elif action == "info":
                return await self.client.get_job_info(arguments["job_id"])
            elif action == "stop":
                return await self.client.stop_job(arguments["job_id"])

        # Console tools
        elif name == "msf_console":
            action = arguments["action"]
            if action == "create":
                return await self.client.console_create()
            elif action == "list":
                return await self.client.console_list()
            elif action == "destroy":
                return await self.client.console_destroy(arguments["console_id"])
            elif action == "read":
                return await self.client.console_read(arguments["console_id"])
            elif action == "write":
                return await self.client.console_write(arguments["console_id"], arguments["data"])

        return {"error": True, "message": f"Unknown tool: {name}"}

    async def run(self) -> None:
        """Run the MCP server."""
        logger.info(f"Starting {self.settings.server_name} v{self.settings.server_version}")

        try:
            # Connect to Metasploit
            await self.client.connect()
            logger.info("Connected to Metasploit RPC")

            # Run MCP server
            async with stdio_server() as (read_stream, write_stream):
                await self.server.run(
                    read_stream,
                    write_stream,
                    self.server.create_initialization_options(),
                )
        finally:
            await self.client.disconnect()
            logger.info("Disconnected from Metasploit RPC")


async def main() -> None:
    """Main entry point."""
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    )

    server = MetasploitMCPServer()
    await server.run()


if __name__ == "__main__":
    asyncio.run(main())
