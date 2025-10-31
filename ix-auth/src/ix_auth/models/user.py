"""User DTO models for authentication.

These are lightweight models (not stored in database) for handling
user data transfer between layers.
"""

from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, EmailStr


class UserCreate(BaseModel):
    """DTO for creating a new user."""

    email: EmailStr
    name: str
    azure_oid: str | None = None
    is_active: bool = True


class UserWithRoles(BaseModel):
    """DTO for user with their roles (API response)."""

    id: UUID
    email: str
    name: str
    is_active: bool
    last_login: datetime | None
    roles: list[str]  # Role names
    permissions: list[str] = []  # Format: "resource:action"
    created_at: datetime | None
    updated_at: datetime | None
    photo_url: str | None = None  # URL to user's profile photo


class CurrentUser(BaseModel):
    """DTO for authenticated user context.

    This is the primary model used throughout the application to represent
    the currently authenticated user and their permissions.
    """

    id: UUID
    email: str
    name: str
    roles: list[str]
    permissions: list[str]  # Format: "resource:action"
    tenant_id: UUID | None = None  # NULL = InsurX admin (cross-tenant access)
    tenant_type: str | None = None  # 'broker' | 'underwriter' | None
    photo_url: str | None = None  # URL to user's profile photo
