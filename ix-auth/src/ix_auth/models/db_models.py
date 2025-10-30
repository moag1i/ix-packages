"""Database models for authentication using ff-storage PydanticModel.

Auth models use:
- No temporal versioning (users don't need SCD2)
- Soft delete for users (is_active flag)
- Basic timestamps (created_at, updated_at, last_login)
- Stored in configurable schema (default: public, can be ix_admin)
"""

from datetime import datetime
from typing import Any, ClassVar
from uuid import UUID

from ff_storage.pydantic_support import PydanticModel
from pydantic import EmailStr, Field, field_validator


class User(PydanticModel):
    """
    User account model.

    Represents a user in the system with authentication credentials
    and profile information. Users can be authenticated via Azure AD
    or mock tokens for development.

    Examples:
        User(
            email="john.doe@example.com",
            name="John Doe",
            azure_oid="12345678-1234-1234-1234-123456789012",
            is_active=True
        )
    """

    __table_name__: ClassVar[str] = "users"
    __schema__: ClassVar[str] = "public"  # Can be overridden to ix_admin
    __temporal_strategy__: ClassVar[str] = "none"  # No versioning for auth data
    __soft_delete__: ClassVar[bool] = True  # Use is_active flag
    __multi_tenant__: ClassVar[bool] = False  # Auth is system-wide

    # ==================== IDENTITY ====================

    email: EmailStr = Field(
        ...,
        description="User email address (unique identifier)",
        max_length=255,
    )

    name: str = Field(
        ...,
        description="User full name",
        max_length=255,
    )

    azure_oid: str | None = Field(
        None,
        description="Azure AD Object ID (unique per Azure tenant)",
        max_length=255,
    )

    # ==================== TENANT CONTEXT ====================

    tenant_id: UUID | None = Field(
        None,
        description="Tenant ID for B2B multi-tenant isolation. NULL = InsurX admin (cross-tenant access)",
    )

    tenant_type: str | None = Field(
        None,
        description="Tenant type: 'broker' | 'underwriter' | None. NULL = InsurX admin",
        max_length=20,
    )

    # ==================== STATUS ====================

    is_active: bool = Field(
        True,
        description="Whether user account is active",
    )

    is_system: bool = Field(
        False,
        description="System user flag (cannot be deleted)",
    )

    # ==================== TIMESTAMPS ====================

    last_login: datetime | None = Field(
        None,
        description="Last successful login timestamp",
    )


class Role(PydanticModel):
    """
    Role model for RBAC.

    Roles group permissions and are assigned to users.
    System roles (admin, underwriter, broker, viewer) cannot be deleted.

    Examples:
        Role(
            name="underwriter",
            description="Can manage rules and evaluate SUIs",
            is_system=True
        )
    """

    __table_name__: ClassVar[str] = "roles"
    __schema__: ClassVar[str] = "public"
    __temporal_strategy__: ClassVar[str] = "none"
    __soft_delete__: ClassVar[bool] = False  # Roles are not soft deleted
    __multi_tenant__: ClassVar[bool] = False

    # ==================== BASIC INFO ====================

    name: str = Field(
        ...,
        description="Role name (unique). Example: 'admin', 'underwriter', 'broker'",
        max_length=100,
    )

    description: str | None = Field(
        None,
        description="Role description",
        max_length=1000,
    )

    is_system: bool = Field(
        False,
        description="System role flag (cannot be deleted)",
    )


class Permission(PydanticModel):
    """
    Permission model for fine-grained access control.

    Permissions follow the format: resource:action
    Examples: "sui:read", "rules:write", "evaluations:read"

    Resources: sui, rules, evaluations, admin
    Actions: read, write
    """

    __table_name__: ClassVar[str] = "permissions"
    __schema__: ClassVar[str] = "public"
    __temporal_strategy__: ClassVar[str] = "none"
    __soft_delete__: ClassVar[bool] = False
    __multi_tenant__: ClassVar[bool] = False

    # ==================== PERMISSION DEFINITION ====================

    resource: str = Field(
        ...,
        description="Resource name. Example: 'sui', 'rules', 'evaluations', 'admin'",
        max_length=100,
    )

    action: str = Field(
        ...,
        description="Action name. Example: 'read', 'write'",
        max_length=50,
    )

    description: str | None = Field(
        None,
        description="Permission description",
        max_length=1000,
    )

    @property
    def name(self) -> str:
        """Get permission name in resource:action format."""
        return f"{self.resource}:{self.action}"


class UserRole(PydanticModel):
    """
    User-Role association model (many-to-many).

    Links users to roles with assignment tracking.
    """

    __table_name__: ClassVar[str] = "user_roles"
    __schema__: ClassVar[str] = "public"
    __temporal_strategy__: ClassVar[str] = "none"
    __soft_delete__: ClassVar[bool] = False
    __multi_tenant__: ClassVar[bool] = False

    # ==================== RELATIONSHIPS ====================

    user_id: UUID = Field(
        ...,
        description="User ID",
    )

    role_id: UUID = Field(
        ...,
        description="Role ID",
    )

    # ==================== AUDIT ====================

    assigned_by: UUID | None = Field(
        None,
        description="ID of user who assigned this role",
    )

    assigned_at: datetime | None = Field(
        None,
        description="Role assignment timestamp",
    )


class RolePermission(PydanticModel):
    """
    Role-Permission association model (many-to-many).

    Links roles to permissions.
    """

    __table_name__: ClassVar[str] = "role_permissions"
    __schema__: ClassVar[str] = "public"
    __temporal_strategy__: ClassVar[str] = "none"
    __soft_delete__: ClassVar[bool] = False
    __multi_tenant__: ClassVar[bool] = False

    # ==================== RELATIONSHIPS ====================

    role_id: UUID = Field(
        ...,
        description="Role ID",
    )

    permission_id: UUID = Field(
        ...,
        description="Permission ID",
    )


class AuthLog(PydanticModel):
    """
    Authentication event log for audit trail.

    Records login, logout, failed auth attempts, and other auth events.
    """

    __table_name__: ClassVar[str] = "auth_logs"
    __schema__: ClassVar[str] = "public"
    __temporal_strategy__: ClassVar[str] = "none"
    __soft_delete__: ClassVar[bool] = False
    __multi_tenant__: ClassVar[bool] = False

    # ==================== EVENT INFO ====================

    user_id: UUID | None = Field(
        None,
        description="User ID (null for failed login attempts)",
    )

    event_type: str = Field(
        ...,
        description="Event type. Example: 'login', 'logout', 'failed_login', 'token_refresh'",
        max_length=50,
    )

    event_details: dict[str, Any] | None = Field(
        None,
        description="Additional event details as JSON",
    )

    @field_validator("event_details", mode="before")
    @classmethod
    def ensure_event_details(cls, value):
        """Ensure event_details is never None."""
        if value is None:
            return {}
        return value

    # ==================== REQUEST INFO ====================

    ip_address: str | None = Field(
        None,
        description="Client IP address",
        max_length=45,  # IPv6 length
    )

    user_agent: str | None = Field(
        None,
        description="Client user agent string",
    )


# ==================== MULTI-TENANT MAPPING ====================


class AzureTenantMapping(PydanticModel):
    """
    Maps Azure AD tenant IDs to InsurX tenant IDs for B2B multi-tenant support.

    When a user from a broker or underwriter organization logs in via Azure AD,
    this table maps their Azure tenant ID to our internal tenant ID for data isolation.

    Examples:
        AzureTenantMapping(
            azure_tenant_id="12345678-1234-1234-1234-123456789012",
            insurx_tenant_id="aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
            tenant_name="Marsh Brokerage",
            tenant_type="broker",
            is_active=True
        )
    """

    __table_name__: ClassVar[str] = "azure_tenant_mappings"
    __schema__: ClassVar[str] = "public"
    __temporal_strategy__: ClassVar[str] = "none"
    __soft_delete__: ClassVar[bool] = False
    __multi_tenant__: ClassVar[bool] = False  # Mapping table is global

    # ==================== MAPPING ====================

    azure_tenant_id: str = Field(
        ...,
        description="Azure AD tenant ID (GUID)",
        max_length=255,
    )

    insurx_tenant_id: UUID = Field(
        ...,
        description="InsurX internal tenant ID",
    )

    tenant_name: str = Field(
        ...,
        description="Tenant display name. Example: 'Marsh', 'Convex', 'Aon'",
        max_length=255,
    )

    tenant_type: str = Field(
        ...,
        description="Tenant type: 'broker' or 'underwriter'",
        max_length=20,
    )

    # ==================== STATUS ====================

    is_active: bool = Field(
        True,
        description="Whether this tenant mapping is active",
    )