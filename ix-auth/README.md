# ix-auth

Shared authentication and authorization package for InsurX APIs. Provides OAuth/RBAC functionality with support for both Azure AD and mock authentication providers.

## Features

- 🔐 **JWT-based authentication** with configurable secrets and algorithms
- 🏢 **Azure AD OAuth 2.0** integration with OIDC support
- 🧪 **Mock authentication** for development and testing
- 🎭 **Role-based access control (RBAC)** with fine-grained permissions
- ⚙️ **Configurable environment prefixes** for multi-service deployments
- 🔌 **FastAPI integration** via middleware and dependency injection
- 📊 **Audit logging** for authentication events
- 🏗️ **Type-safe** with Pydantic models throughout

## Installation

Install the package using `uv` with a path reference:

```bash
# From ix-ds or fenix-agents directory
uv add ix-auth --path ../ix-packages/ix-auth
```

Or add directly to `pyproject.toml`:

```toml
dependencies = [
    "ix-auth @ file:///../ix-packages/ix-auth",
    # other dependencies...
]
```

## Quick Start

### 1. Basic Setup (InsurX)

```python
# src/shared/config/__init__.py
from ix_auth import AuthSettings

# Use IX_DS_AUTH_* environment variables
auth_settings = AuthSettings.with_prefix("IX_DS_AUTH_")
```

### 2. Middleware Registration

```python
# src/api/app.py
from fastapi import FastAPI
from ix_auth.middleware.fastapi import AuthMiddleware
from src.shared.config import auth_settings
from src.shared.db import admin_db_pool

app = FastAPI()

# Register auth middleware
app.add_middleware(
    AuthMiddleware,
    settings=auth_settings,
    admin_db_pool=admin_db_pool,
)
```

### 3. Protecting Endpoints

```python
# src/api/routes/data.py
from fastapi import APIRouter, Depends
from ix_auth.dependencies.fastapi import require_permission, get_current_user
from ix_auth.models import CurrentUser

router = APIRouter()

@router.get("/api/v2/users/me")
async def get_me(user: CurrentUser = Depends(get_current_user)):
    """Get current user info."""
    return user

@router.post("/api/v2/inscoping/suis")
async def create_sui(
    sui: SUIRequest,
    user: CurrentUser = Depends(require_permission("sui:write"))
):
    """Create SUI (requires sui:write permission)."""
    # User is authenticated and has sui:write permission
    return {"created_by": user.email}
```

### 4. Mock Authentication (Development)

```python
# Generate mock token for testing
from ix_auth.providers.mock import MockAuthProvider

provider = MockAuthProvider(auth_settings)
token = provider.generate_token(role="admin", user_email="dev@insurx.com")
print(f"Bearer {token.access_token}")

# Use in requests
# curl -H "Authorization: Bearer {token}" http://localhost:8000/api/v2/inscoping/suis
```

## Configuration

### Environment Variables

The package uses environment variables with configurable prefixes:

```bash
# Core Settings
{PREFIX}ENABLED=true                     # Enable/disable authentication
{PREFIX}DEFAULT_ROLE=viewer              # Default role for new users

# JWT Settings
{PREFIX}JWT_SECRET=your-secret-here      # REQUIRED: Secret for signing tokens
{PREFIX}JWT_ALGORITHM=HS256              # JWT algorithm (HS256 or RS256)
{PREFIX}JWT_EXPIRE_MINUTES=60            # Token expiration (minutes)
{PREFIX}JWT_REFRESH_EXPIRE_DAYS=7        # Refresh token expiration (days)

# Mock Auth (Development)
{PREFIX}MOCK_ENABLED=true                # Enable mock authentication
{PREFIX}MOCK_USER_EMAIL=dev@insurx.com   # Default mock user email
{PREFIX}MOCK_USER_NAME=Dev User          # Default mock user name
{PREFIX}MOCK_DEFAULT_ROLE=admin          # Default mock user role

# Azure AD (Production)
{PREFIX}AZURE_ENABLED=false              # Enable Azure AD OAuth
{PREFIX}AZURE_TENANT_ID=...              # Azure tenant ID
{PREFIX}AZURE_CLIENT_ID=...              # Azure app client ID
{PREFIX}AZURE_CLIENT_SECRET=...          # Azure app secret
{PREFIX}AZURE_REDIRECT_URI=...           # OAuth redirect URI

# Admin Database
{PREFIX}ADMIN_DB_HOST=localhost          # Database host
{PREFIX}ADMIN_DB_PORT=5432               # Database port
{PREFIX}ADMIN_DB_NAME=ix_admin           # Database name
{PREFIX}ADMIN_DB_USER=postgres           # Database user
{PREFIX}ADMIN_DB_PASSWORD=postgres       # Database password
{PREFIX}ADMIN_DB_SCHEMA=public           # Database schema for auth tables
```

### Configurable Prefixes

Different services can use different environment prefixes:

```python
# InsurX Data Service (uses IX_DS_AUTH_*)
auth_settings = AuthSettings.with_prefix("IX_DS_AUTH_")

# Fenix Agents (uses FENIX_AUTH_*)
auth_settings = AuthSettings.with_prefix("FENIX_AUTH_")

# Custom Service (uses MY_SERVICE_AUTH_*)
auth_settings = AuthSettings.with_prefix("MY_SERVICE_AUTH_")
```

## Advanced Usage

### Permission-Based Access Control

```python
from ix_auth.dependencies.fastapi import (
    require_permission,
    require_any_permission,
    require_all_permissions,
)

# Single permission
@router.post("/api/items", dependencies=[Depends(require_permission("items:write"))])
async def create_item():
    pass

# Any of multiple permissions
@router.get("/api/reports", dependencies=[Depends(require_any_permission("reports:read", "admin:read"))])
async def get_reports():
    pass

# All permissions required
@router.delete("/api/system", dependencies=[Depends(require_all_permissions("admin:write", "system:manage"))])
async def system_operation():
    pass
```

### Role-Based Access Control

```python
from ix_auth.dependencies.fastapi import require_role, require_any_role

# Single role
@router.post("/api/admin", dependencies=[Depends(require_role("admin"))])
async def admin_only():
    pass

# Any of multiple roles
@router.get("/api/data", dependencies=[Depends(require_any_role("admin", "underwriter"))])
async def restricted_data():
    pass
```

### Pre-configured Dependencies

```python
from ix_auth.dependencies.fastapi import (
    require_admin,
    require_underwriter,
    require_broker,
    require_sui_read,
    require_sui_write,
)

# Use pre-configured role/permission checks
@router.post("/api/admin/users", dependencies=[Depends(require_admin)])
async def manage_users():
    pass
```

### Custom Auth Providers

```python
from ix_auth.providers.base import BaseAuthProvider

class CustomAuthProvider(BaseAuthProvider):
    """Custom authentication provider."""

    async def validate_token(self, token: str) -> TokenPayload:
        # Custom token validation logic
        pass

    def generate_token(self, **kwargs) -> Token:
        # Custom token generation
        pass
```

### Database Schema Configuration

```python
from ix_auth.repositories import UserRepository

# Use custom schema (default is "public")
user_repo = UserRepository(db_pool, schema="ix_admin")

# Or configure via settings
auth_settings = AuthSettings.with_prefix("IX_DS_AUTH_")
auth_settings.admin_db_schema = "custom_schema"
```

## API Routes

The package includes optional OAuth routes that can be mounted:

```python
from fastapi import FastAPI
from ix_auth.routes import create_auth_router

app = FastAPI()

# Create and mount auth routes
auth_router = create_auth_router(
    settings=auth_settings,
    db_pool=admin_db_pool,
)
app.include_router(auth_router, prefix="/auth", tags=["auth"])
```

Available endpoints:
- `POST /auth/login` - Initiate Azure AD OAuth flow
- `GET /auth/callback` - OAuth callback endpoint
- `POST /auth/token` - Exchange auth code for tokens
- `GET /auth/me` - Get current user info
- `POST /auth/logout` - Logout current user
- `POST /auth/mock-token` - Generate mock token (dev only)
- `GET /auth/health` - Auth system health check

## Database Schema

The authentication system uses the following tables:

- `users` - User accounts
- `roles` - System roles (admin, underwriter, broker, viewer)
- `permissions` - Fine-grained permissions (resource:action format)
- `user_roles` - User-role assignments
- `role_permissions` - Role-permission mappings
- `auth_logs` - Authentication audit trail

### Initialization

Initialize roles and permissions on first run:

```python
from ix_auth.utils.roles import initialize_roles_and_permissions

async def startup():
    await initialize_roles_and_permissions(db_pool, schema="public")
```

## Default Roles and Permissions

### System Roles

- `admin` - Full system access
- `underwriter` - Underwriting operations
- `broker` - Broker operations
- `viewer` - Read-only access

### Base Permissions

- `sui:read`, `sui:write` - SUI management
- `rules:read`, `rules:write` - Rules management
- `evaluations:read`, `evaluations:write` - Evaluations management
- `admin:read`, `admin:write` - Admin operations

## Testing

### Unit Tests

```bash
cd ix-auth
uv sync
uv run pytest tests/unit/
```

### Integration Tests

```bash
# Requires test database
uv run pytest tests/integration/
```

### Mock Token Testing

```python
# Generate test token
from ix_auth.providers.mock import MockAuthProvider

mock = MockAuthProvider(auth_settings)
admin_token = mock.generate_token(role="admin")
broker_token = mock.generate_token(role="broker", user_email="broker@test.com")
```

## Migration Guide

### From Embedded Auth to ix-auth Package

1. **Update imports**:
```python
# Before
from src.auth.models.token import TokenPayload
from src.api.dependencies.auth import require_auth

# After
from ix_auth.models import TokenPayload
from ix_auth.dependencies.fastapi import require_auth
```

2. **Update configuration**:
```python
# Before (hardcoded prefix)
auth_settings = AuthSettings()  # Uses IX_DS_AUTH_*

# After (configurable prefix)
auth_settings = AuthSettings.with_prefix("IX_DS_AUTH_")
```

3. **Update middleware registration**:
```python
# Before
from src.api.middleware.auth import AuthMiddleware

# After
from ix_auth.middleware.fastapi import AuthMiddleware
```

## Troubleshooting

### Common Issues

1. **Import errors**: Ensure package is installed via `uv add ix-auth --path ../ix-packages/ix-auth`

2. **JWT Secret not set**: Set `{PREFIX}JWT_SECRET` environment variable

3. **Database connection issues**: Verify admin database credentials and connectivity

4. **Permission denied**: Check user roles and permissions in database

5. **Token validation failures**: Verify JWT secret matches between services

### Debug Mode

Enable debug logging:

```python
import logging
logging.getLogger("ix_auth").setLevel(logging.DEBUG)
```

## Contributing

1. Follow existing code patterns
2. Add tests for new features
3. Update documentation
4. Run linting: `uv run ruff check src/`
5. Run type checking: `uv run mypy src/`

## License

Proprietary - InsurX Global

## Support

For issues or questions, contact the InsurX development team.