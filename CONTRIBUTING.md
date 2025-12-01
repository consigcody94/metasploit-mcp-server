# Contributing to Metasploit MCP Server

Thank you for your interest in contributing to Metasploit MCP Server! This document provides guidelines and information for contributors.

## Code of Conduct

By participating in this project, you agree to maintain a respectful and inclusive environment. We expect all contributors to:

- Be respectful and inclusive
- Accept constructive criticism gracefully
- Focus on what's best for the community
- Show empathy towards others

## Getting Started

### Prerequisites

- Python 3.10 or higher
- Git
- Metasploit Framework (for integration testing)

### Development Setup

1. **Fork and clone the repository**:
   ```bash
   git clone https://github.com/yourusername/metasploit-mcp-server.git
   cd metasploit-mcp-server
   ```

2. **Create a virtual environment**:
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. **Install development dependencies**:
   ```bash
   pip install -e ".[dev]"
   ```

4. **Install pre-commit hooks**:
   ```bash
   pre-commit install
   ```

## Development Workflow

### Branching Strategy

- `main` - Stable release branch
- `develop` - Development branch for next release
- `feature/*` - Feature branches
- `fix/*` - Bug fix branches
- `docs/*` - Documentation branches

### Making Changes

1. **Create a feature branch**:
   ```bash
   git checkout -b feature/your-feature-name
   ```

2. **Make your changes** following the coding standards

3. **Write or update tests** for your changes

4. **Run the test suite**:
   ```bash
   pytest
   ```

5. **Run linters**:
   ```bash
   black src/ tests/
   ruff check src/ tests/
   mypy src/
   ```

6. **Commit your changes**:
   ```bash
   git commit -m "feat: add your feature description"
   ```

### Commit Message Format

We follow the [Conventional Commits](https://www.conventionalcommits.org/) specification:

- `feat:` - New feature
- `fix:` - Bug fix
- `docs:` - Documentation only
- `style:` - Code style changes (formatting, etc.)
- `refactor:` - Code refactoring
- `test:` - Adding or updating tests
- `chore:` - Maintenance tasks

Examples:
```
feat: add session upgrade tool
fix: handle connection timeout gracefully
docs: update README with new configuration options
```

## Pull Request Process

1. **Update documentation** if needed
2. **Add tests** for new functionality
3. **Ensure all tests pass**
4. **Update CHANGELOG.md** with your changes
5. **Submit the pull request** with a clear description

### PR Checklist

- [ ] Tests pass locally
- [ ] Code follows project style guidelines
- [ ] Documentation updated (if applicable)
- [ ] CHANGELOG.md updated
- [ ] Commit messages follow conventions

## Testing

### Running Tests

```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=src/metasploit_mcp --cov-report=html

# Run specific test file
pytest tests/test_client.py -v

# Run tests matching a pattern
pytest -k "test_session" -v
```

### Writing Tests

- Place tests in the `tests/` directory
- Use pytest fixtures for common setup
- Mock external dependencies (Metasploit RPC)
- Aim for high code coverage

Example test:
```python
import pytest
from metasploit_mcp.config import Settings

def test_default_settings():
    settings = Settings()
    assert settings.msf_host == "127.0.0.1"
    assert settings.msf_port == 55553
```

## Code Style

### Python Style Guide

- Follow PEP 8 guidelines
- Use type hints for all functions
- Maximum line length: 100 characters
- Use docstrings for public functions

### Formatting

We use:
- **Black** for code formatting
- **Ruff** for linting
- **mypy** for type checking

### Example Code Style

```python
from __future__ import annotations

from typing import Any

async def my_function(
    param1: str,
    param2: int = 10,
    *,
    keyword_only: bool = False,
) -> dict[str, Any]:
    """
    Short description of the function.

    Args:
        param1: Description of param1
        param2: Description of param2
        keyword_only: Description of keyword_only

    Returns:
        Description of return value

    Raises:
        ValueError: When param1 is empty
    """
    if not param1:
        raise ValueError("param1 cannot be empty")

    return {"result": param1, "count": param2}
```

## Security Considerations

When contributing to this security-focused project:

1. **Never commit credentials** or sensitive data
2. **Review code for security issues** before submitting
3. **Report security vulnerabilities** privately to maintainers
4. **Follow secure coding practices**
5. **Be mindful of dual-use implications**

## Documentation

### Updating Documentation

- Keep README.md updated with new features
- Document new configuration options
- Add docstrings to all public functions
- Update type hints as needed

### Documentation Style

- Use clear, concise language
- Include code examples where helpful
- Keep formatting consistent

## Release Process

Releases are managed by maintainers. The process:

1. Update version in `pyproject.toml`
2. Update CHANGELOG.md
3. Create release tag
4. Build and publish to PyPI

## Getting Help

- Open an issue for bugs or feature requests
- Join discussions in GitHub Discussions
- Tag maintainers for urgent issues

## Recognition

Contributors will be recognized in:
- CHANGELOG.md for their contributions
- GitHub contributors list
- README acknowledgments (for significant contributions)

Thank you for contributing to Metasploit MCP Server!
