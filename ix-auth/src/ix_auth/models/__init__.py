"""Authentication models."""

from .token import (
    Token,
    TokenPayload,
    TokenRequest,
    AzureTokenResponse,
    AzureUserInfo,
    MockTokenRequest,
)
from .user import (
    CurrentUser,
    UserCreate,
    UserWithRoles,
)
from .db_models import (
    User,
    Role,
    Permission,
    UserRole,
    RolePermission,
    AuthLog,
    AzureTenantMapping,
)

__all__ = [
    # Token models
    "Token",
    "TokenPayload",
    "TokenRequest",
    "AzureTokenResponse",
    "AzureUserInfo",
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
]