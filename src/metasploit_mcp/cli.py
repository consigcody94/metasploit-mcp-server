"""
Command-line interface for Metasploit MCP Server.

Provides easy startup and configuration options for the MCP server.
"""

from __future__ import annotations

import asyncio
import logging
import sys
from typing import Optional

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from metasploit_mcp import __version__
from metasploit_mcp.config import LogLevel, Settings
from metasploit_mcp.server import MetasploitMCPServer

app = typer.Typer(
    name="metasploit-mcp",
    help="Metasploit MCP Server - AI Agent Integration for Penetration Testing",
    add_completion=False,
)

console = Console()


def setup_logging(level: LogLevel, log_file: Optional[str] = None) -> None:
    """Configure logging."""
    handlers = [logging.StreamHandler(sys.stderr)]

    if log_file:
        handlers.append(logging.FileHandler(log_file))

    logging.basicConfig(
        level=level.value,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
        handlers=handlers,
    )


def print_banner() -> None:
    """Print the startup banner."""
    banner = Text()
    banner.append(
        "╔══════════════════════════════════════════════════════════════╗\n", style="bright_red"
    )
    banner.append("║", style="bright_red")
    banner.append("      __  __      _                  _       _ _   ", style="red")
    banner.append("║\n", style="bright_red")
    banner.append("║", style="bright_red")
    banner.append("     |  \\/  | ___| |_ __ _ ___ _ __ | | ___ (_) |_ ", style="red")
    banner.append("║\n", style="bright_red")
    banner.append("║", style="bright_red")
    banner.append("     | |\\/| |/ _ \\ __/ _` / __| '_ \\| |/ _ \\| | __|", style="red")
    banner.append("║\n", style="bright_red")
    banner.append("║", style="bright_red")
    banner.append("     | |  | |  __/ || (_| \\__ \\ |_) | | (_) | | |_ ", style="red")
    banner.append("║\n", style="bright_red")
    banner.append("║", style="bright_red")
    banner.append("     |_|  |_|\\___|\\__\\__,_|___/ .__/|_|\\___/|_|\\__|", style="red")
    banner.append("║\n", style="bright_red")
    banner.append("║", style="bright_red")
    banner.append("                              |_|                  ", style="red")
    banner.append("║\n", style="bright_red")
    banner.append("║", style="bright_red")
    banner.append(
        "            __  __  ____ ____    ____                      ", style="bright_cyan"
    )
    banner.append("║\n", style="bright_red")
    banner.append("║", style="bright_red")
    banner.append(
        "           |  \\/  |/ ___|  _ \\  / ___|  ___ _ ____   _____ _ __ ", style="bright_cyan"
    )
    banner.append("║\n", style="bright_red")
    banner.append("║", style="bright_red")
    banner.append(
        "           | |\\/| | |   | |_) | \\___ \\ / _ \\ '__\\ \\ / / _ \\ '__|",
        style="bright_cyan",
    )
    banner.append("║\n", style="bright_red")
    banner.append("║", style="bright_red")
    banner.append(
        "           | |  | | |___|  __/   ___) |  __/ |   \\ V /  __/ |   ", style="bright_cyan"
    )
    banner.append("║\n", style="bright_red")
    banner.append("║", style="bright_red")
    banner.append(
        "           |_|  |_|\\____|_|     |____/ \\___|_|    \\_/ \\___|_|   ", style="bright_cyan"
    )
    banner.append("║\n", style="bright_red")
    banner.append("║", style="bright_red")
    banner.append(
        f"                                                v{__version__}".ljust(60),
        style="bright_yellow",
    )
    banner.append("║\n", style="bright_red")
    banner.append(
        "╚══════════════════════════════════════════════════════════════╝", style="bright_red"
    )

    console.print(banner)
    console.print()


@app.command()
def serve(
    host: str = typer.Option(
        "127.0.0.1",
        "--host",
        "-h",
        help="Metasploit RPC host",
        envvar="METASPLOIT_MCP_MSF_HOST",
    ),
    port: int = typer.Option(
        55553,
        "--port",
        "-p",
        help="Metasploit RPC port",
        envvar="METASPLOIT_MCP_MSF_PORT",
    ),
    password: str = typer.Option(
        ...,
        "--password",
        "-P",
        help="Metasploit RPC password",
        envvar="METASPLOIT_MCP_MSF_PASSWORD",
        prompt=True,
        hide_input=True,
    ),
    username: str = typer.Option(
        "msf",
        "--username",
        "-u",
        help="Metasploit RPC username",
        envvar="METASPLOIT_MCP_MSF_USERNAME",
    ),
    ssl: bool = typer.Option(
        True,
        "--ssl/--no-ssl",
        help="Use SSL for RPC connection",
        envvar="METASPLOIT_MCP_MSF_SSL",
    ),
    ssl_verify: bool = typer.Option(
        False,
        "--ssl-verify/--no-ssl-verify",
        help="Verify SSL certificate",
        envvar="METASPLOIT_MCP_MSF_SSL_VERIFY",
    ),
    log_level: LogLevel = typer.Option(
        LogLevel.INFO,
        "--log-level",
        "-l",
        help="Logging level",
        envvar="METASPLOIT_MCP_LOG_LEVEL",
    ),
    log_file: Optional[str] = typer.Option(
        None,
        "--log-file",
        help="Log file path",
        envvar="METASPLOIT_MCP_LOG_FILE",
    ),
    dry_run: bool = typer.Option(
        False,
        "--dry-run",
        help="Enable dry-run mode (no actual exploitation)",
        envvar="METASPLOIT_MCP_DRY_RUN_MODE",
    ),
    no_banner: bool = typer.Option(
        False,
        "--no-banner",
        help="Don't show startup banner",
    ),
) -> None:
    """Start the Metasploit MCP Server."""
    if not no_banner:
        print_banner()

    setup_logging(log_level, log_file)

    # Create settings
    settings = Settings(
        msf_host=host,
        msf_port=port,
        msf_username=username,
        msf_password=password,
        msf_ssl=ssl,
        msf_ssl_verify=ssl_verify,
        log_level=log_level,
        log_file=log_file,
        dry_run_mode=dry_run,
    )

    console.print(
        Panel(
            f"[bright_green]Starting MCP Server[/]\n\n"
            f"[cyan]MSF Host:[/] {settings.msf_host}:{settings.msf_port}\n"
            f"[cyan]SSL:[/] {'Enabled' if settings.msf_ssl else 'Disabled'}\n"
            f"[cyan]Dry Run:[/] {'Enabled' if settings.dry_run_mode else 'Disabled'}\n"
            f"[cyan]Log Level:[/] {settings.log_level.value}",
            title="[bright_red]Metasploit MCP Server[/]",
            border_style="bright_red",
        )
    )

    try:
        server = MetasploitMCPServer(settings)
        asyncio.run(server.run())
    except KeyboardInterrupt:
        console.print("\n[yellow]Server stopped by user[/]")
    except Exception as e:
        console.print(f"\n[red]Error: {e}[/]")
        raise typer.Exit(1)


@app.command()
def version() -> None:
    """Show version information."""
    console.print(f"[bright_red]Metasploit MCP Server[/] v{__version__}")


@app.command()
def config() -> None:
    """Show current configuration from environment."""
    settings = Settings()

    table = Table(title="Current Configuration", border_style="bright_red")
    table.add_column("Setting", style="cyan")
    table.add_column("Value", style="green")

    table.add_row("MSF Host", settings.msf_host)
    table.add_row("MSF Port", str(settings.msf_port))
    table.add_row("MSF SSL", "Yes" if settings.msf_ssl else "No")
    table.add_row("MSF Username", settings.msf_username)
    table.add_row(
        "MSF Password", "***" if settings.msf_password.get_secret_value() else "(not set)"
    )
    table.add_row("Log Level", settings.log_level.value)
    table.add_row("Dry Run Mode", "Yes" if settings.dry_run_mode else "No")
    table.add_row("Audit Logging", "Yes" if settings.audit_logging else "No")
    table.add_row("Rate Limiting", "Yes" if settings.rate_limit_enabled else "No")
    table.add_row("Enable Exploits", "Yes" if settings.enable_exploit_tools else "No")
    table.add_row("Enable Sessions", "Yes" if settings.enable_session_tools else "No")
    table.add_row("Enable DB Tools", "Yes" if settings.enable_db_tools else "No")

    console.print(table)


@app.command()
def tools() -> None:
    """List all available MCP tools."""
    table = Table(title="Available MCP Tools", border_style="bright_red")
    table.add_column("Tool", style="bright_cyan")
    table.add_column("Description", style="white")
    table.add_column("Category", style="yellow")

    tools_list = [
        ("msf_version", "Get Metasploit version info", "Core"),
        ("msf_module_stats", "Get module statistics", "Core"),
        ("msf_search", "Search for modules", "Discovery"),
        ("msf_module_info", "Get module details", "Discovery"),
        ("msf_module_options", "Get module options", "Discovery"),
        ("msf_compatible_payloads", "Get compatible payloads", "Discovery"),
        ("msf_list_exploits", "List exploit modules", "Modules"),
        ("msf_list_auxiliary", "List auxiliary modules", "Modules"),
        ("msf_list_post", "List post modules", "Modules"),
        ("msf_list_payloads", "List payloads", "Modules"),
        ("msf_check", "Check vulnerability (safe)", "Exploitation"),
        ("msf_execute", "Execute module", "Exploitation"),
        ("msf_sessions_list", "List active sessions", "Sessions"),
        ("msf_session_run", "Run command in session", "Sessions"),
        ("msf_session_stop", "Terminate session", "Sessions"),
        ("msf_session_upgrade", "Upgrade to Meterpreter", "Sessions"),
        ("msf_db_status", "Database status", "Database"),
        ("msf_workspaces", "Manage workspaces", "Database"),
        ("msf_hosts", "Manage hosts", "Database"),
        ("msf_services", "List services", "Database"),
        ("msf_vulns", "List vulnerabilities", "Database"),
        ("msf_creds", "List credentials", "Database"),
        ("msf_jobs", "Manage background jobs", "Jobs"),
        ("msf_console", "Console interaction", "Console"),
    ]

    for tool, desc, category in tools_list:
        table.add_row(tool, desc, category)

    console.print(table)


def main() -> None:
    """Main entry point."""
    app()


if __name__ == "__main__":
    main()
