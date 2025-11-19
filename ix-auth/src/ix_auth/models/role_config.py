"""Pydantic models for role and permission configuration."""

from pydantic import BaseModel, Field, field_validator


class PermissionConfig(BaseModel):
    """Permission configuration for a service."""

    resource: str = Field(..., description="Resource name (e.g., 'refdata', 'sui', 'rules')")
    action: str = Field(..., description="Action name (e.g., 'read', 'write', 'delete')")
    description: str = Field(..., description="Human-readable permission description")

    @property
    def name(self) -> str:
        """Get permission name in resource:action format."""
        return f"{self.resource}:{self.action}"

    def __hash__(self):
        """Make hashable for set operations."""
        return hash((self.resource, self.action))


class RoleConfig(BaseModel):
    """Role configuration for a service."""

    name: str = Field(..., description="Role name (e.g., 'admin', 'refdata-reader')")
    description: str = Field(..., description="Human-readable role description")
    is_system: bool = Field(
        default=False, description="Whether this is a system role (cannot be deleted)"
    )
    permissions: list[str] = Field(
        default_factory=list, description="List of permission names in 'resource:action' format"
    )

    @field_validator("permissions")
    @classmethod
    def validate_permission_format(cls, v: list[str]) -> list[str]:
        """Validate that permissions are in correct format."""
        for perm in v:
            if ":" not in perm:
                raise ValueError(
                    f"Permission '{perm}' must be in format 'resource:action' (e.g., 'refdata:read')"
                )
            parts = perm.split(":")
            if len(parts) != 2:
                raise ValueError(
                    f"Permission '{perm}' must have exactly one colon separating resource and action"
                )
            if not parts[0] or not parts[1]:
                raise ValueError(f"Permission '{perm}' cannot have empty resource or action")
        return v

    @field_validator("name")
    @classmethod
    def validate_role_name(cls, v: str) -> str:
        """Validate role name format."""
        if not v:
            raise ValueError("Role name cannot be empty")
        if len(v) > 100:
            raise ValueError("Role name must be 100 characters or less")
        # Allow alphanumeric, dash, underscore
        if not all(c.isalnum() or c in "-_" for c in v):
            raise ValueError(
                "Role name can only contain alphanumeric characters, dashes, and underscores"
            )
        return v


class RolePermissionConfig(BaseModel):
    """Complete role and permission configuration for a service."""

    service_name: str = Field(..., description="Service name (e.g., 'ix-ref', 'ix-ds')")
    roles: list[RoleConfig] = Field(..., min_length=1, description="List of roles to create")
    permissions: list[PermissionConfig] = Field(
        ..., min_length=1, description="List of permissions to create"
    )

    @field_validator("roles")
    @classmethod
    def validate_roles_unique(cls, v: list[RoleConfig]) -> list[RoleConfig]:
        """Validate that role names are unique."""
        role_names = [role.name for role in v]
        if len(role_names) != len(set(role_names)):
            raise ValueError("Role names must be unique within the configuration")
        return v

    @field_validator("permissions")
    @classmethod
    def validate_permissions_unique(cls, v: list[PermissionConfig]) -> list[PermissionConfig]:
        """Validate that permissions are unique."""
        perm_names = [perm.name for perm in v]
        if len(perm_names) != len(set(perm_names)):
            raise ValueError("Permission names must be unique within the configuration")
        return v

    @field_validator("service_name")
    @classmethod
    def validate_service_name(cls, v: str) -> str:
        """Validate service name format."""
        if not v:
            raise ValueError("Service name cannot be empty")
        if len(v) > 50:
            raise ValueError("Service name must be 50 characters or less")
        return v

    def get_role_permissions_map(self) -> dict[str, list[str]]:
        """Get mapping of role names to permission names."""
        return {role.name: role.permissions for role in self.roles}

    def validate_role_permissions_exist(self) -> None:
        """Validate that all permissions referenced in roles actually exist in the permissions list."""
        available_perms = {perm.name for perm in self.permissions}

        for role in self.roles:
            for perm in role.permissions:
                if perm not in available_perms:
                    raise ValueError(
                        f"Role '{role.name}' references permission '{perm}' which is not defined in permissions list"
                    )

    def model_post_init(self, __context) -> None:
        """Run additional validation after model initialization."""
        self.validate_role_permissions_exist()
