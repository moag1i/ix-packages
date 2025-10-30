# Contributing to ix-auth

Thank you for your interest in contributing to the ix-auth package! This document provides guidelines and instructions for contributing.

## Development Setup

### Prerequisites

- Python 3.10 or higher
- uv (modern Python package manager)
- Git

### Setting up the Development Environment

1. Clone the repository:
```bash
git clone https://github.com/InsurX/ix-packages.git
cd ix-packages/ix-auth
```

2. Create a virtual environment and install dependencies:
```bash
uv venv
uv sync --dev
```

3. Install pre-commit hooks:
```bash
uv run pre-commit install
```

## Development Workflow

### Making Changes

1. Create a new branch for your feature/fix:
```bash
git checkout -b feature/your-feature-name
```

2. Make your changes and ensure they follow our coding standards.

3. Write or update tests as needed.

4. Run the test suite:
```bash
uv run pytest tests/
```

5. Run linting and formatting:
```bash
uv run ruff check src/ tests/
uv run ruff format src/ tests/
uv run mypy src/ix_auth
```

### Testing

We use pytest for testing. Please ensure:

- All new features have corresponding tests
- All tests pass before submitting a PR
- Test coverage remains above 80%

Run tests with coverage:
```bash
uv run pytest tests/ --cov=ix_auth --cov-report=term-missing
```

### Code Style

We use:
- **ruff** for linting and formatting
- **mypy** for type checking
- **Black** formatting style (via ruff)

All code must:
- Have type hints
- Pass mypy strict mode
- Follow PEP 8 guidelines
- Include docstrings for public APIs

### Commit Messages

Follow the conventional commits specification:

- `feat:` New feature
- `fix:` Bug fix
- `docs:` Documentation changes
- `style:` Code style changes (formatting, etc.)
- `refactor:` Code refactoring
- `test:` Test additions or changes
- `chore:` Maintenance tasks

Example:
```bash
git commit -m "feat: add support for custom token expiration"
```

## Submitting Changes

### Pull Request Process

1. Update the CHANGELOG.md with your changes under "Unreleased"

2. Ensure all tests pass and coverage is maintained

3. Update documentation if needed

4. Submit a pull request with:
   - Clear description of changes
   - Link to any related issues
   - Screenshots if UI changes

5. Wait for code review and address feedback

### Pull Request Checklist

- [ ] Tests pass locally
- [ ] Code follows style guidelines
- [ ] Type hints are included
- [ ] Documentation is updated
- [ ] CHANGELOG.md is updated
- [ ] Commit messages follow convention

## Architecture Guidelines

### Adding New Authentication Providers

1. Create a new provider in `src/ix_auth/providers/`
2. Inherit from `BaseAuthProvider`
3. Implement required methods
4. Add configuration to `AuthSettings`
5. Update documentation

### Adding New Middleware

1. Create middleware in `src/ix_auth/middleware/`
2. Follow FastAPI/Starlette patterns
3. Include comprehensive error handling
4. Add tests for all code paths

### Database Models

1. Use ff-storage PydanticModel base class
2. Include proper indexes
3. Follow naming conventions
4. Add migrations if schema changes

## Testing Guidelines

### Unit Tests

- Test individual functions/methods
- Mock external dependencies
- Use fixtures for common setup
- Keep tests focused and fast

### Integration Tests

- Test full workflows
- Use real database connections (test database)
- Test authentication flows end-to-end
- Include error scenarios

## Security Considerations

When contributing authentication/authorization code:

1. Never log sensitive information (tokens, passwords)
2. Always validate and sanitize inputs
3. Use constant-time comparisons for secrets
4. Follow OWASP guidelines
5. Report security issues privately

## Getting Help

- Open an issue for bugs or feature requests
- Join our Slack channel for discussions
- Check existing issues before creating new ones
- Use discussions for questions

## License

By contributing, you agree that your contributions will be licensed under the MIT License.