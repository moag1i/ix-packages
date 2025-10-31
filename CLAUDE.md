# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

InsurX Packages (`ix-packages`) - Monorepo for shared packages used across the InsurX ecosystem. This directory is designed to hold reusable infrastructure packages that eliminate code duplication across multiple InsurX services.

**Purpose**: Central location for creating and maintaining shared packages following the pattern of existing packages like `ff-storage` and `ff-parsers`.

## Current State

The repository is currently empty except for documentation (`BUILD_FF_AUTH_PACKAGE.md`) that provides detailed instructions for creating the first package: `ix-auth` - a shared authentication/authorization package.

## Related Services

The packages created here will be consumed by:
- **ix-ds**: Core data service (../ix-ds/) - Insurance policy management API
- **ix-app**: Frontend application (../ix-app/) - React-based UI
- **fenix-agents**: Document processing service
- **ix-cli**: Command-line tools (../ix-cli/)

## Package Development Commands

### Creating a New Package

```bash
# Create package directory structure
mkdir -p <package-name>/src/<package_name_underscore>
cd <package-name>

# Initialize with pyproject.toml
touch pyproject.toml README.md .gitignore
```

### Building and Testing Packages

```bash
# Install package in development mode from consuming project
cd ../ix-ds  # or other consuming project
uv add <package-name> --path ../ix-packages/<package-name>

# Run tests within package directory
cd ../ix-packages/<package-name>
uv sync
uv run pytest

# Linting and formatting
uv run ruff check src/
uv run ruff format src/
uv run mypy src/
```

### Package Publishing (Internal)

Packages are installed locally via path references, not published to PyPI:

```toml
# In consuming project's pyproject.toml
dependencies = [
    "ix-auth @ file:///../ix-packages/ix-auth",
    # or with uv: uv add ix-auth --path ../ix-packages/ix-auth
]
```

## Architecture Patterns

### Package Structure Template

All packages should follow this structure:
```
<package-name>/
├── pyproject.toml           # Package configuration
├── README.md                # Usage documentation
├── .gitignore
├── src/
│   └── <package_name>/      # Use underscores, not hyphens
│       ├── __init__.py      # Package exports
│       ├── config.py        # Settings with Pydantic
│       ├── models/          # Pydantic models/DTOs
│       ├── utils/           # Utility functions
│       └── ...              # Domain-specific modules
└── tests/
    ├── unit/                # Unit tests
    └── integration/         # Integration tests
```

### Key Design Principles

1. **Configurable Prefixes**: Settings should support different environment variable prefixes (e.g., `IX_DS_*`, `FENIX_*`)
2. **Dependency Injection**: Don't create database connections or external resources - accept them as parameters
3. **Framework Agnostic Core**: Core logic should work without framework dependencies where possible
4. **Type Safety**: Use Pydantic for all data models and settings
5. **Comprehensive Testing**: Include both unit and integration tests

## Reference Implementation

The `BUILD_FF_AUTH_PACKAGE.md` file contains a complete specification for building the `ix-auth` package, including:
- Detailed package structure
- Source files from `/Users/bgmoag/PycharmProjects/InsurX/worktrees/oauth-integration/`
- Configuration patterns with customizable environment prefixes
- FastAPI middleware and dependencies
- Azure AD and mock authentication providers
- JWT utilities and permission management

## Environment Configuration

Packages should use Pydantic Settings with configurable prefixes:

```python
# Example from ix-auth package design
class AuthSettings(BaseSettings):
    @classmethod
    def with_prefix(cls, prefix: str) -> "AuthSettings":
        """Create settings with custom environment prefix."""
        config = SettingsConfigDict(
            env_prefix=prefix,  # e.g., "IX_DS_AUTH_" or "FENIX_AUTH_"
            env_file=".env",
            case_sensitive=False,
        )
        return cls(model_config=config)
```

## Development Tools

- **uv**: Modern Python package manager (replacement for pip/poetry)
- **ruff**: Fast Python linter and formatter
- **mypy**: Static type checker
- **pytest**: Testing framework
- **ff-logger**: Structured logging (InsurX standard)
- **ff-storage**: PostgreSQL connection pooling (InsurX standard)
