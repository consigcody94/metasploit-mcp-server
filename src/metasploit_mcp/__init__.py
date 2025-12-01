"""
Metasploit MCP Server - Advanced Model Context Protocol integration for Metasploit Framework.

This module provides AI agents with secure, controlled access to Metasploit's capabilities
for authorized penetration testing, security research, and CTF challenges.
"""

__version__ = "1.0.0"
__author__ = "Security Research Team"

from metasploit_mcp.client import MsfRpcClient
from metasploit_mcp.config import Settings
from metasploit_mcp.server import MetasploitMCPServer

__all__ = ["MetasploitMCPServer", "MsfRpcClient", "Settings", "__version__"]
