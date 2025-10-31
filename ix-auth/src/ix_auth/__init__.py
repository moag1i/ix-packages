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
from .dependencies import (
    get_current_user,
    get_current_user_required,
    # Convenience
    require_admin,
    require_all_permissions,
    require_any_permission,
    require_any_role,
    # Basic auth
    require_auth,
    require_broker,
    # Permission-based
    require_permission,
    # Role-based
    require_role,
    require_underwriter,
)
from .helpers import (
    assign_role_to_user,
    get_user_with_roles_and_permissions,
    log_auth_event,
    provision_user_from_azure,
)
from .middleware import AuthMiddleware
from .models import (
    AuthLog,
    AzureTenantMapping,
    # User DTOs
    CurrentUser,
    MockTokenRequest,
    Permission,
    Role,
    RolePermission,
    # Token models
    Token,
    TokenPayload,
    TokenRequest,
    # Database models
    User,
    UserCreate,
    UserRole,
    UserWithRoles,
)
from .providers import (
    AzureADProvider,
    BaseAuthProvider,
    JWTTokenProvider,
)
from .repositories import UserRepository
from .utils.roles import initialize_roles_and_permissions, initialize_tenant_mappings

__version__ = "0.1.0"

__all__ = [
    # Configuration
    "AuthSettings",
    # Token models
    "Token",
    "TokenPayload",
    "TokenRequest",
    "MockTokenRequest",
    # User DTOs
    "CurrentUser",
    "UserCreate",
    "UserWithRoles",
    # Database models
    "User",
    "Role",
    "Permission",
    "UserRole",
    "RolePermission",
    "AuthLog",
    "AzureTenantMapping",
    # Providers
    "BaseAuthProvider",
    "JWTTokenProvider",
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
    "initialize_tenant_mappings",
    # Helpers
    "provision_user_from_azure",
    "get_user_with_roles_and_permissions",
    "assign_role_to_user",
    "log_auth_event",
]
