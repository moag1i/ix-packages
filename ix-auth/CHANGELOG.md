# Changelog

All notable changes to the ix-auth package will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0] - 2025-01-30

### Added
- Initial release of ix-auth package
- JWT-based authentication with configurable secrets
- Azure AD OAuth 2.0 integration for enterprise SSO
- Mock authentication provider for development/testing
- Role-Based Access Control (RBAC) with permissions
- FastAPI middleware for automatic request authentication
- FastAPI dependencies for authorization decorators
- Configurable environment variable prefixes for multi-service deployment
- Support for different services using different configuration prefixes
- User repository for database operations
- Comprehensive data models for authentication/authorization
- GitHub Actions CI/CD pipeline for automated testing and deployment
- Support for multiple package registries (GitHub, AWS CodeArtifact, Azure Artifacts, private PyPI)
- Unit tests for core functionality
- Type hints throughout the codebase

### Features
- **Configurable Prefixes**: Each service can use its own environment variable prefix (e.g., `IX_DS_AUTH_`, `FENIX_AUTH_`)
- **Mock Provider**: Pre-configured users (admin, user, viewer) for development
- **Azure AD Integration**: Full OAuth 2.0 flow with Microsoft Graph API
- **JWT Utilities**: Token creation, validation, and decoding
- **RBAC Support**: Fine-grained permissions and role-based access control
- **FastAPI Integration**: Middleware and dependencies for seamless integration
- **Database Models**: ff-storage compatible models for user management

### Security
- JWT token validation with configurable algorithms
- Secure token storage and transmission
- Azure AD enterprise authentication support
- Environment-based configuration for secrets

### Documentation
- Comprehensive README with usage examples
- API documentation for all public interfaces
- Migration guide from embedded authentication

[0.1.0]: https://github.com/InsurX/ix-packages/releases/tag/ix-auth-v0.1.0
