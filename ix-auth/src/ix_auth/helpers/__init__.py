"""Helper functions for user management and authentication operations.

Provides centralized, reusable functions using ff-storage v3 patterns.
"""

from .user_management import (
    assign_role_to_user,
    get_user_with_roles_and_permissions,
    log_auth_event,
    provision_user_from_azure,
)

__all__ = [
    "provision_user_from_azure",
    "get_user_with_roles_and_permissions",
    "assign_role_to_user",
    "log_auth_event",
]
