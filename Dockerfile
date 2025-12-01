# Metasploit MCP Server Dockerfile
# Multi-stage build for minimal production image

# =============================================================================
# Build Stage
# =============================================================================
FROM python:3.12-slim as builder

WORKDIR /app

# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# Create virtual environment
RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Install dependencies
COPY pyproject.toml .
COPY src/ src/
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir .

# =============================================================================
# Production Stage
# =============================================================================
FROM python:3.12-slim as production

LABEL maintainer="Security Research Team"
LABEL description="Metasploit MCP Server - AI Agent Integration for Penetration Testing"
LABEL version="1.0.0"

# Create non-root user for security
RUN groupadd -r msfmcp && useradd -r -g msfmcp msfmcp

WORKDIR /app

# Copy virtual environment from builder
COPY --from=builder /opt/venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Copy application
COPY --chown=msfmcp:msfmcp src/ src/
COPY --chown=msfmcp:msfmcp README.md .

# Set environment defaults
ENV METASPLOIT_MCP_MSF_HOST=host.docker.internal \
    METASPLOIT_MCP_MSF_PORT=55553 \
    METASPLOIT_MCP_MSF_SSL=true \
    METASPLOIT_MCP_MSF_SSL_VERIFY=false \
    METASPLOIT_MCP_LOG_LEVEL=INFO \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

# Switch to non-root user
USER msfmcp

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python -c "import metasploit_mcp; print('healthy')" || exit 1

# Entry point
ENTRYPOINT ["metasploit-mcp"]
CMD ["serve"]

# =============================================================================
# Development Stage
# =============================================================================
FROM production as development

USER root

# Install development dependencies
RUN pip install --no-cache-dir pytest pytest-asyncio pytest-cov black ruff mypy

USER msfmcp

CMD ["serve", "--dry-run"]
