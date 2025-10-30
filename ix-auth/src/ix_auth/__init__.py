"""ix-auth: Shared authentication and authorization for InsurX APIs.

This package provides:
- JWT-based authentication with configurable secrets
- Azure AD OAuth 2.0 integration
- Mock authentication for development
- Role-based access control (RBAC)
- FastAPI middleware and dependencies
- Configurable environment prefixes
"""

from .config import AuthSettings
from .models import (
    # Token models
    Token,
    TokenPayload,
    TokenRequest,
    # User DTOs
    CurrentUser,
    UserCreate,
    UserWithRoles,
)
from .providers import (
    BaseAuthProvider,
    MockAuthProvider,
    AzureADProvider,
)
from .middleware import AuthMiddleware
from .dependencies import (
    # Basic auth
    require_auth,
    get_current_user,
    get_current_user_required,
    # Permission-based
    require_permission,
    require_any_permission,
    require_all_permissions,
    # Role-based
    require_role,
    require_any_role,
    # Convenience
    require_admin,
    require_underwriter,
    require_broker,
)
from .repositories import UserRepository
from .utils.roles import initialize_roles_and_permissions

__version__ = "0.1.0"

__all__ = [
    # Configuration
    "AuthSettings",
    # Token models
    "Token",
    "TokenPayload",
    "TokenRequest",
    # User DTOs
    "CurrentUser",
    "UserCreate",
    "UserWithRoles",
    # Providers
    "BaseAuthProvider",
    "MockAuthProvider",
    "AzureADProvider",
    # Middleware
    "AuthMiddleware",
    # Dependencies
    "require_auth",
    "get_current_user",
    "get_current_user_required",
    "require_permission",
    "require_any_permission",
    "require_all_permissions",
    "require_role",
    "require_any_role",
    "require_admin",
    "require_underwriter",
    "require_broker",
    # Repository
    "UserRepository",
    # Initialization
    "initialize_roles_and_permissions",
]