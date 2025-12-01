# Metasploit MCP Server

<div align="center">

```
    __  __      _                  _       _ _
   |  \/  | ___| |_ __ _ ___ _ __ | | ___ (_) |_
   | |\/| |/ _ \ __/ _` / __| '_ \| |/ _ \| | __|
   | |  | |  __/ || (_| \__ \ |_) | | (_) | | |_
   |_|  |_|\___|\__\__,_|___/ .__/|_|\___/|_|\__|
                            |_|
          __  __  ____ ____    ____
         |  \/  |/ ___|  _ \  / ___|  ___ _ ____   _____ _ __
         | |\/| | |   | |_) | \___ \ / _ \ '__\ \ / / _ \ '__|
         | |  | | |___|  __/   ___) |  __/ |   \ V /  __/ |
         |_|  |_|\____|_|     |____/ \___|_|    \_/ \___|_|
```

**Advanced Model Context Protocol Server for Metasploit Framework**

*Empowering AI agents with controlled penetration testing capabilities*

[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![MCP Protocol](https://img.shields.io/badge/MCP-1.0-green.svg)](https://modelcontextprotocol.io)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Code style: black](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black)
[![Security: bandit](https://img.shields.io/badge/security-bandit-purple.svg)](https://github.com/PyCQA/bandit)

[Features](#features) | [Installation](#installation) | [Quick Start](#quick-start) | [Documentation](#documentation) | [Security](#security)

</div>

---

## Overview

Metasploit MCP Server is a production-ready implementation of the [Model Context Protocol](https://modelcontextprotocol.io) that provides AI agents (Claude, GPT, etc.) with secure, controlled access to the Metasploit Framework for **authorized penetration testing**, **security research**, and **CTF challenges**.

### Why This Project?

- **AI-Powered Pentesting**: Enable AI agents to conduct sophisticated security assessments
- **Safe by Design**: Built-in safety controls, dry-run mode, and audit logging
- **Professional Grade**: Rate limiting, connection pooling, and comprehensive error handling
- **Fully Configurable**: Whitelist/blacklist modules, control features, set limits

## Features

### Core Capabilities

| Feature | Description |
|---------|-------------|
| **Module Discovery** | Search, list, and inspect 4000+ Metasploit modules |
| **Exploit Execution** | Run exploits with safety controls and confirmation |
| **Session Management** | Manage shells, Meterpreter sessions, and post-exploitation |
| **Database Integration** | Full access to Metasploit's workspace and findings database |
| **Payload Generation** | Generate and encode payloads with various encoders |
| **Job Management** | Monitor and control background jobs |

### Security Features

- **Dry-Run Mode**: Test workflows without actual exploitation
- **Module Whitelist/Blacklist**: Control which modules can be executed
- **Rate Limiting**: Prevent RPC API abuse
- **Audit Logging**: Track all operations for compliance
- **Session Limits**: Control maximum concurrent sessions
- **SSL/TLS Support**: Secure RPC communication

### MCP Protocol Support

- **40+ Tools**: Comprehensive coverage of Metasploit functionality
- **9 Resources**: Real-time access to modules, sessions, and database
- **4 Prompts**: Pre-built workflows for common scenarios
- **Full Async**: Non-blocking operations for better performance

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        AI Agent (Claude, GPT, etc.)              │
└─────────────────────────────┬───────────────────────────────────┘
                              │ MCP Protocol (stdio)
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                     Metasploit MCP Server                        │
│  ┌───────────────┐  ┌───────────────┐  ┌───────────────┐        │
│  │   Tools (40+) │  │ Resources (9) │  │  Prompts (4)  │        │
│  └───────┬───────┘  └───────┬───────┘  └───────┬───────┘        │
│          │                  │                  │                 │
│  ┌───────▼──────────────────▼──────────────────▼───────┐        │
│  │              Safety & Audit Layer                    │        │
│  │  • Module filtering  • Rate limiting  • Audit logs   │        │
│  └───────────────────────┬─────────────────────────────┘        │
│                          │                                       │
│  ┌───────────────────────▼─────────────────────────────┐        │
│  │           Async Metasploit RPC Client               │        │
│  │  • Connection pooling  • Retry logic  • msgpack     │        │
│  └───────────────────────┬─────────────────────────────┘        │
└──────────────────────────┼──────────────────────────────────────┘
                           │ MSGRPC (msgpack over HTTP/HTTPS)
                           ▼
┌─────────────────────────────────────────────────────────────────┐
│                    Metasploit Framework                          │
│  ┌─────────┐  ┌──────────┐  ┌─────────┐  ┌──────────┐          │
│  │ Modules │  │ Sessions │  │   DB    │  │   Jobs   │          │
│  └─────────┘  └──────────┘  └─────────┘  └──────────┘          │
└─────────────────────────────────────────────────────────────────┘
```

## Installation

### Prerequisites

- Python 3.10 or higher
- Metasploit Framework with RPC enabled
- (Optional) PostgreSQL for Metasploit database

### Using pip

```bash
pip install metasploit-mcp-server
```

### From Source

```bash
git clone https://github.com/yourusername/metasploit-mcp-server.git
cd metasploit-mcp-server
pip install -e ".[dev]"
```

### Using Docker

```bash
docker pull yourusername/metasploit-mcp-server
docker run -it --rm \
  -e METASPLOIT_MCP_MSF_HOST=host.docker.internal \
  -e METASPLOIT_MCP_MSF_PASSWORD=yourpassword \
  yourusername/metasploit-mcp-server
```

## Quick Start

### 1. Start Metasploit RPC

```bash
# Start msfrpcd with a password
msfrpcd -P yourpassword -S -a 127.0.0.1

# Or from msfconsole
msf6> load msgrpc Pass=yourpassword
```

### 2. Configure the MCP Server

Create a `.env` file or set environment variables:

```bash
# .env
METASPLOIT_MCP_MSF_HOST=127.0.0.1
METASPLOIT_MCP_MSF_PORT=55553
METASPLOIT_MCP_MSF_PASSWORD=yourpassword
METASPLOIT_MCP_MSF_SSL=true
METASPLOIT_MCP_LOG_LEVEL=INFO
```

### 3. Run the Server

```bash
# Using the CLI
metasploit-mcp serve --password yourpassword

# Or with environment variables
metasploit-mcp serve

# Dry-run mode (safe testing)
metasploit-mcp serve --dry-run
```

### 4. Configure Your AI Client

#### Claude Desktop

Add to `~/Library/Application Support/Claude/claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "metasploit": {
      "command": "metasploit-mcp",
      "args": ["serve", "--password", "yourpassword"],
      "env": {
        "METASPLOIT_MCP_MSF_HOST": "127.0.0.1"
      }
    }
  }
}
```

#### Other MCP Clients

The server uses stdio transport. Connect using:
- **Command**: `metasploit-mcp serve --password yourpassword`
- **Transport**: stdio

## Documentation

### Available Tools

<details>
<summary><b>Core Tools</b></summary>

| Tool | Description |
|------|-------------|
| `msf_version` | Get Metasploit version and system info |
| `msf_module_stats` | Get statistics about available modules |

</details>

<details>
<summary><b>Module Discovery</b></summary>

| Tool | Description |
|------|-------------|
| `msf_search` | Search modules by keyword, CVE, platform |
| `msf_module_info` | Get detailed module information |
| `msf_module_options` | Get configurable module options |
| `msf_compatible_payloads` | Get payloads compatible with exploit |
| `msf_list_exploits` | List all exploit modules |
| `msf_list_auxiliary` | List all auxiliary modules |
| `msf_list_post` | List all post-exploitation modules |
| `msf_list_payloads` | List all payload modules |
| `msf_list_encoders` | List all encoder modules |
| `msf_list_nops` | List all NOP modules |
| `msf_list_evasion` | List all evasion modules |

</details>

<details>
<summary><b>Exploitation</b></summary>

| Tool | Description |
|------|-------------|
| `msf_check` | Check if target is vulnerable (safe) |
| `msf_execute` | Execute a module (requires authorization) |

</details>

<details>
<summary><b>Session Management</b></summary>

| Tool | Description |
|------|-------------|
| `msf_sessions_list` | List all active sessions |
| `msf_session_info` | Get session details |
| `msf_session_run` | Run command in session |
| `msf_session_stop` | Terminate a session |
| `msf_session_upgrade` | Upgrade shell to Meterpreter |
| `msf_session_compatible_modules` | Get compatible post modules |

</details>

<details>
<summary><b>Database</b></summary>

| Tool | Description |
|------|-------------|
| `msf_db_status` | Check database connection |
| `msf_workspaces` | Manage workspaces |
| `msf_hosts` | Manage hosts in database |
| `msf_services` | List discovered services |
| `msf_vulns` | List vulnerabilities |
| `msf_creds` | List credentials |
| `msf_loots` | List captured loot |
| `msf_import_scan` | Import scan results |

</details>

<details>
<summary><b>Jobs & Console</b></summary>

| Tool | Description |
|------|-------------|
| `msf_jobs` | Manage background jobs |
| `msf_console` | Interact with console |

</details>

### Available Resources

| Resource URI | Description |
|--------------|-------------|
| `msf://modules/exploits` | All exploit modules |
| `msf://modules/auxiliary` | All auxiliary modules |
| `msf://modules/post` | All post modules |
| `msf://modules/payloads` | All payload modules |
| `msf://sessions` | Active sessions |
| `msf://jobs` | Background jobs |
| `msf://db/hosts` | Database hosts |
| `msf://db/services` | Database services |
| `msf://db/vulns` | Database vulnerabilities |

### Available Prompts

| Prompt | Description |
|--------|-------------|
| `pentest_recon` | Reconnaissance workflow |
| `vuln_assessment` | Vulnerability assessment |
| `exploit_guide` | Exploitation guidance |
| `post_exploitation` | Post-exploitation workflow |

### Configuration Reference

All settings can be configured via environment variables with the `METASPLOIT_MCP_` prefix:

| Variable | Default | Description |
|----------|---------|-------------|
| `MSF_HOST` | `127.0.0.1` | Metasploit RPC host |
| `MSF_PORT` | `55553` | Metasploit RPC port |
| `MSF_SSL` | `true` | Use SSL/TLS |
| `MSF_SSL_VERIFY` | `false` | Verify SSL certificate |
| `MSF_USERNAME` | `msf` | RPC username |
| `MSF_PASSWORD` | *(required)* | RPC password |
| `LOG_LEVEL` | `INFO` | Logging level |
| `DRY_RUN_MODE` | `false` | Enable dry-run mode |
| `RATE_LIMIT_ENABLED` | `true` | Enable rate limiting |
| `RATE_LIMIT_CALLS` | `100` | Max calls per period |
| `RATE_LIMIT_PERIOD` | `60` | Rate limit period (seconds) |
| `MAX_CONCURRENT_SESSIONS` | `10` | Max sessions |
| `BLOCKED_MODULES` | *(empty)* | Comma-separated blocked modules |
| `ENABLE_EXPLOIT_TOOLS` | `true` | Enable exploit tools |
| `ENABLE_SESSION_TOOLS` | `true` | Enable session tools |
| `ENABLE_DB_TOOLS` | `true` | Enable database tools |
| `AUDIT_LOGGING` | `true` | Enable audit logging |

## Security

### Important Notices

> **Warning**: This tool provides access to powerful exploitation capabilities. Only use it:
> - On systems you own or have explicit written authorization to test
> - In isolated lab environments
> - For authorized penetration testing engagements
> - For CTF competitions and security research

### Built-in Safeguards

1. **Dry-Run Mode**: Test workflows without actual exploitation
2. **Module Filtering**: Whitelist/blacklist specific modules
3. **Rate Limiting**: Prevent API abuse
4. **Audit Logging**: Complete operation trail
5. **Session Limits**: Control resource usage

### Recommended Practices

```bash
# Always start in dry-run mode for testing
metasploit-mcp serve --dry-run

# Block dangerous modules in production
export METASPLOIT_MCP_BLOCKED_MODULES="exploit/multi/handler,auxiliary/dos/*"

# Enable full audit logging
export METASPLOIT_MCP_AUDIT_LOGGING=true
```

## Examples

### Basic Reconnaissance

```python
# AI Agent interaction example
# 1. Search for scanner modules
result = await msf_search("type:auxiliary scanner/portscan")

# 2. Get module info
info = await msf_module_info("auxiliary", "scanner/portscan/tcp")

# 3. Run the scan
scan_result = await msf_execute(
    module_type="auxiliary",
    module_name="scanner/portscan/tcp",
    options={"RHOSTS": "192.168.1.0/24", "PORTS": "22,80,443"}
)
```

### Vulnerability Check

```python
# Check for EternalBlue without exploitation
result = await msf_check(
    module_type="exploit",
    module_name="windows/smb/ms17_010_eternalblue",
    options={"RHOSTS": "192.168.1.100"}
)
```

### Session Interaction

```python
# List sessions
sessions = await msf_sessions_list()

# Run command in Meterpreter
output = await msf_session_run(
    session_id=1,
    command="sysinfo"
)

# Get compatible post modules
modules = await msf_session_compatible_modules(session_id=1)
```

## Development

### Setup Development Environment

```bash
git clone https://github.com/yourusername/metasploit-mcp-server.git
cd metasploit-mcp-server
python -m venv venv
source venv/bin/activate
pip install -e ".[dev]"
pre-commit install
```

### Running Tests

```bash
# Run all tests
pytest

# With coverage
pytest --cov=src/metasploit_mcp --cov-report=html

# Run specific test
pytest tests/test_client.py -v
```

### Code Quality

```bash
# Format code
black src/ tests/

# Lint
ruff check src/ tests/

# Type check
mypy src/
```

## Contributing

Contributions are welcome! Please read our [Contributing Guide](CONTRIBUTING.md) for details.

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- [Metasploit Framework](https://github.com/rapid7/metasploit-framework) - The world's most used penetration testing framework
- [Model Context Protocol](https://modelcontextprotocol.io) - Standardizing AI agent tool interfaces
- [pymetasploit3](https://github.com/DanMcInerney/pymetasploit3) - Python Metasploit RPC client reference

## Disclaimer

This tool is provided for educational and authorized security testing purposes only. The authors are not responsible for any misuse or damage caused by this tool. Always ensure you have proper authorization before conducting any security testing.

---

<div align="center">

**[Report Bug](https://github.com/yourusername/metasploit-mcp-server/issues)** | **[Request Feature](https://github.com/yourusername/metasploit-mcp-server/issues)** | **[Documentation](https://github.com/yourusername/metasploit-mcp-server/wiki)**

Made with a]]) by Security Researchers

</div>
