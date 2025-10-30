"""Authentication dependencies."""

from .fastapi import (
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
    require_sui_read,
    require_sui_write,
    require_rules_read,
    require_rules_write,
    require_evaluations_read,
    require_evaluations_write,
)

__all__ = [
    # Basic auth
    "require_auth",
    "get_current_user",
    "get_current_user_required",
    # Permission-based
    "require_permission",
    "require_any_permission",
    "require_all_permissions",
    # Role-based
    "require_role",
    "require_any_role",
    # Convenience
    "require_admin",
    "require_underwriter",
    "require_broker",
    "require_sui_read",
    "require_sui_write",
    "require_rules_read",
    "require_rules_write",
    "require_evaluations_read",
    "require_evaluations_write",
]