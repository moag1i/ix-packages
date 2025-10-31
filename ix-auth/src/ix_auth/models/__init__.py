"""Authentication models."""

from .db_models import AuthLog, AzureTenantMapping, Permission, Role, RolePermission, User, UserRole
from .token import (
    AzureTokenResponse,
    AzureUserInfo,
    MockTokenRequest,
    Token,
    TokenPayload,
    TokenRequest,
)
from .user import CurrentUser, UserCreate, UserWithRoles

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
