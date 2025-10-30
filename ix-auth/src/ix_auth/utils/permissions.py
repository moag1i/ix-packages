"""Permission utility functions."""

from typing import List


def has_permission(user_permissions: List[str], required: str) -> bool:
    """
    Check if user has a specific permission.

    Args:
        user_permissions: List of user's permissions
        required: Required permission string (e.g., "sui:write")

    Returns:
        True if user has the required permission
    """
    return required in user_permissions


def has_any_permission(
    user_permissions: List[str],
    required: List[str],
) -> bool:
    """
    Check if user has ANY of the required permissions.

    Args:
        user_permissions: List of user's permissions
        required: List of required permissions

    Returns:
        True if user has at least one of the required permissions
    """
    if not required:
        return True
    return any(perm in user_permissions for perm in required)


def has_all_permissions(
    user_permissions: List[str],
    required: List[str],
) -> bool:
    """
    Check if user has ALL of the required permissions.

    Args:
        user_permissions: List of user's permissions
        required: List of required permissions

    Returns:
        True if user has all of the required permissions
    """
    if not required:
        return True
    return all(perm in user_permissions for perm in required)


def has_role(user_roles: List[str], required: str) -> bool:
    """
    Check if user has a specific role.

    Args:
        user_roles: List of user's roles
        required: Required role name (e.g., "admin")

    Returns:
        True if user has the required role
    """
    return required in user_roles


def has_any_role(user_roles: List[str], required: List[str]) -> bool:
    """
    Check if user has ANY of the required roles.

    Args:
        user_roles: List of user's roles
        required: List of required roles

    Returns:
        True if user has at least one of the required roles
    """
    if not required:
        return True
    return any(role in user_roles for role in required)


def has_all_roles(user_roles: List[str], required: List[str]) -> bool:
    """
    Check if user has ALL of the required roles.

    Args:
        user_roles: List of user's roles
        required: List of required roles

    Returns:
        True if user has all of the required roles
    """
    if not required:
        return True
    return all(role in user_roles for role in required)


def parse_permission(permission: str) -> tuple[str, str]:
    """
    Parse a permission string into resource and action.

    Args:
        permission: Permission string (e.g., "sui:write")

    Returns:
        Tuple of (resource, action)

    Raises:
        ValueError: If permission format is invalid
    """
    if ":" not in permission:
        raise ValueError(f"Invalid permission format: {permission}")

    parts = permission.split(":", 1)
    if len(parts) != 2:
        raise ValueError(f"Invalid permission format: {permission}")

    resource, action = parts
    if not resource or not action:
        raise ValueError(f"Invalid permission format: {permission}")

    return resource, action


def format_permission(resource: str, action: str) -> str:
    """
    Format a permission string from resource and action.

    Args:
        resource: Resource name (e.g., "sui")
        action: Action name (e.g., "write")

    Returns:
        Formatted permission string (e.g., "sui:write")
    """
    return f"{resource}:{action}"