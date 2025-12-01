# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 1.x.x   | :white_check_mark: |
| < 1.0   | :x:                |

## Reporting a Vulnerability

We take security seriously. If you discover a security vulnerability in Metasploit MCP Server, please report it responsibly.

### How to Report

1. **Do NOT** create a public GitHub issue for security vulnerabilities
2. Email the maintainers directly with details
3. Include:
   - Description of the vulnerability
   - Steps to reproduce
   - Potential impact
   - Suggested fix (if any)

### What to Expect

- Acknowledgment within 48 hours
- Regular updates on the fix progress
- Credit in the release notes (unless you prefer anonymity)
- Coordinated disclosure timeline

## Security Considerations

### This Tool's Purpose

Metasploit MCP Server provides AI agents with access to penetration testing capabilities. It is designed for:

- Authorized security testing
- Security research
- CTF competitions
- Educational purposes

### Built-in Safeguards

1. **Dry-Run Mode**: Test workflows without exploitation
2. **Module Filtering**: Whitelist/blacklist modules
3. **Rate Limiting**: Prevent API abuse
4. **Audit Logging**: Track all operations
5. **Session Limits**: Control resource usage

### Recommended Security Practices

#### Network Security

```bash
# Only bind to localhost unless absolutely necessary
METASPLOIT_MCP_MSF_HOST=127.0.0.1

# Use SSL/TLS for remote connections
METASPLOIT_MCP_MSF_SSL=true

# Consider using SSH tunnels for remote access
ssh -L 55553:localhost:55553 user@metasploit-host
```

#### Access Control

```bash
# Use strong passwords
METASPLOIT_MCP_MSF_PASSWORD=$(openssl rand -base64 32)

# Limit allowed modules
METASPLOIT_MCP_ALLOWED_MODULES=auxiliary/scanner/*,exploit/windows/*

# Block dangerous modules
METASPLOIT_MCP_BLOCKED_MODULES=exploit/multi/handler,auxiliary/dos/*
```

#### Operational Security

```bash
# Enable audit logging
METASPLOIT_MCP_AUDIT_LOGGING=true

# Start with dry-run mode for new workflows
METASPLOIT_MCP_DRY_RUN_MODE=true

# Limit concurrent sessions
METASPLOIT_MCP_MAX_CONCURRENT_SESSIONS=5
```

### Threat Model

#### Assets to Protect

- Target systems (within authorized scope)
- Credentials and session data
- Audit logs and findings
- The MCP server itself

#### Potential Threats

1. **Unauthorized Access**: Someone gaining access to the MCP server
2. **Scope Creep**: Actions outside authorized testing scope
3. **Data Leakage**: Exposure of credentials or findings
4. **Denial of Service**: Overwhelming the Metasploit instance

#### Mitigations

| Threat | Mitigation |
|--------|------------|
| Unauthorized Access | Strong auth, network isolation |
| Scope Creep | Module filtering, audit logs |
| Data Leakage | Encryption, access controls |
| DoS | Rate limiting, session limits |

## Legal Disclaimer

This software is provided for **authorized security testing only**. Users must:

1. Only test systems they own or have explicit written authorization to test
2. Comply with all applicable laws and regulations
3. Not use this software for malicious purposes
4. Accept full responsibility for their actions

The maintainers are not responsible for:
- Misuse of this software
- Unauthorized access to systems
- Any damages resulting from use of this software

## Compliance

When using this tool, consider:

- **PCI DSS**: Requirements for penetration testing
- **HIPAA**: Healthcare data protection
- **GDPR**: European data protection
- **SOC 2**: Security controls
- **Local Laws**: Computer fraud and abuse laws

Always obtain proper authorization and follow your organization's security policies.

## Contact

For security-related inquiries, contact the maintainers directly.

---

*Remember: With great power comes great responsibility. Use this tool ethically and legally.*
