"""ix-auth: Shared authentication and authorization for InsurX APIs.

This package provides:
- JWT-based authentication with configurable secrets
- Azure AD OAuth 2.0 integration
- Mock authentication for development
- Role-based access control (RBAC)
- FastAPI middleware and dependencies
- Configurable environment prefixes
"""

from importlib.metadata import PackageNotFoundError, version

from .config import AuthSettings
from .dependencies import (  # Convenience; Basic auth; Permission-based; Role-based
    get_current_user,
    get_current_user_required,
    require_admin,
    require_all_permissions,
    require_any_permission,
    require_any_role,
    require_auth,
    require_broker,
    require_permission,
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
from .models import (  # User DTOs; Token models; Database models
    AuthLog,
    AzureTenantMapping,
    CurrentUser,
    MockTokenRequest,
    Permission,
    Role,
    RolePermission,
    Token,
    TokenPayload,
    TokenRequest,
    User,
    UserCreate,
    UserRole,
    UserWithRoles,
)
from .models.role_config import PermissionConfig, RoleConfig, RolePermissionConfig
from .providers import AzureADProvider, BaseAuthProvider, JWTTokenProvider
from .repositories import UserRepository
from .utils.roles import initialize_roles_and_permissions, initialize_tenant_mappings

# Version is read from package metadata (pyproject.toml)
try:
    __version__ = version("ix-auth")
except PackageNotFoundError:
    # Package is not installed, fallback for development
    __version__ = "0.0.0+dev"

__all__ = [
    # Configuration
    "AuthSettings",
    "RolePermissionConfig",
    "RoleConfig",
    "PermissionConfig",
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
