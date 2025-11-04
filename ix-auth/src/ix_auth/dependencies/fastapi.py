"""FastAPI dependencies for authentication and authorization.

Provides dependency functions for:
- Requiring authentication
- Getting current user
- Checking permissions
- Role-based access control
"""

from typing import Annotated

from fastapi import Depends, HTTPException, Request, status

from ..models import CurrentUser, TokenPayload

# ==================== BASIC AUTH DEPENDENCIES ====================


async def require_auth(request: Request) -> TokenPayload:
    """
    Require authentication for endpoint.

    Returns token payload if authenticated, raises 401 if not.

    Usage:
        @app.get("/protected")
        async def protected_endpoint(token: Annotated[TokenPayload, Depends(require_auth)]):
            return {"user": token.email}

    Args:
        request: FastAPI request (injected by middleware)

    Returns:
        TokenPayload from request state

    Raises:
        HTTPException: 401 if not authenticated
    """
    if not request.state.is_authenticated:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required",
            headers={"WWW-Authenticate": "Bearer"},
        )

    return request.state.user


async def get_current_user(request: Request) -> CurrentUser | None:
    """
    Get current authenticated user (optional).

    Returns user context if authenticated, None if not.
    Does not raise error for unauthenticated requests.

    Usage:
        @app.get("/optional-auth")
        async def endpoint(user: Annotated[CurrentUser | None, Depends(get_current_user)]):
            if user:
                return {"message": f"Hello {user.name}"}
            return {"message": "Hello guest"}

    Args:
        request: FastAPI request

    Returns:
        CurrentUser or None
    """
    if not request.state.is_authenticated:
        return None

    token = request.state.user

    # Convert TokenPayload to CurrentUser
    # Note: This uses the enriched payload from middleware
    return CurrentUser(
        id=token.user_id,
        email=token.email,
        name=token.name,
        roles=token.roles,
        permissions=token.permissions,
        tenant_id=token.tenant_id,  # InsurX tenant ID (None = admin)
        tenant_type=token.tenant_type,  # Tenant type for scoping
    )


async def get_current_user_required(
    user: Annotated[CurrentUser | None, Depends(get_current_user)],
) -> CurrentUser:
    """
    Get current authenticated user (required).

    Raises 401 if not authenticated.

    Usage:
        @app.get("/user-required")
        async def endpoint(user: Annotated[CurrentUser, Depends(get_current_user_required)]):
            return {"user": user.email}

    Args:
        user: Current user from get_current_user dependency

    Returns:
        CurrentUser

    Raises:
        HTTPException: 401 if not authenticated
    """
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required",
            headers={"WWW-Authenticate": "Bearer"},
        )

    return user


# ==================== PERMISSION-BASED DEPENDENCIES ====================


def require_permission(permission: str):
    """
    Dependency factory for requiring specific permission.

    Usage:
        @app.post("/sui")
        async def create_sui(
            user: Annotated[CurrentUser, Depends(require_permission("sui:write"))]
        ):
            return {"message": "SUI created"}

    Args:
        permission: Permission string in format "resource:action"

    Returns:
        Dependency function that validates permission
    """

    async def permission_dependency(
        user: Annotated[CurrentUser, Depends(get_current_user_required)],
    ) -> CurrentUser:
        if permission not in user.permissions:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Permission denied: {permission} required",
            )
        return user

    return permission_dependency


def require_any_permission(*permissions: str):
    """
    Dependency factory for requiring ANY of the specified permissions.

    Usage:
        @app.get("/data")
        async def get_data(
            user: Annotated[
                CurrentUser,
                Depends(require_any_permission("sui:read", "rules:read"))
            ]
        ):
            return {"data": "..."}

    Args:
        *permissions: Permission strings

    Returns:
        Dependency function that validates permissions
    """

    async def permission_dependency(
        user: Annotated[CurrentUser, Depends(get_current_user_required)],
    ) -> CurrentUser:
        for perm in permissions:
            if perm in user.permissions:
                return user

        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Permission denied: one of {permissions} required",
        )

    return permission_dependency


def require_all_permissions(*permissions: str):
    """
    Dependency factory for requiring ALL of the specified permissions.

    Usage:
        @app.post("/admin/action")
        async def admin_action(
            user: Annotated[
                CurrentUser,
                Depends(require_all_permissions("admin:read", "admin:write"))
            ]
        ):
            return {"message": "Action completed"}

    Args:
        *permissions: Permission strings

    Returns:
        Dependency function that validates permissions
    """

    async def permission_dependency(
        user: Annotated[CurrentUser, Depends(get_current_user_required)],
    ) -> CurrentUser:
        missing = [p for p in permissions if p not in user.permissions]
        if missing:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Permission denied: {missing} required",
            )
        return user

    return permission_dependency


# ==================== ROLE-BASED DEPENDENCIES ====================


def require_role(role: str):
    """
    Dependency factory for requiring specific role.

    Usage:
        @app.get("/admin")
        async def admin_endpoint(
            user: Annotated[CurrentUser, Depends(require_role("admin"))]
        ):
            return {"message": "Admin access granted"}

    Args:
        role: Role name

    Returns:
        Dependency function that validates role
    """

    async def role_dependency(
        user: Annotated[CurrentUser, Depends(get_current_user_required)],
    ) -> CurrentUser:
        if role not in user.roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Role required: {role}",
            )
        return user

    return role_dependency


def require_any_role(*roles: str):
    """
    Dependency factory for requiring ANY of the specified roles.

    Usage:
        @app.get("/management")
        async def management_endpoint(
            user: Annotated[
                CurrentUser,
                Depends(require_any_role("admin", "underwriter"))
            ]
        ):
            return {"message": "Management access granted"}

    Args:
        *roles: Role names

    Returns:
        Dependency function that validates roles
    """

    async def role_dependency(
        user: Annotated[CurrentUser, Depends(get_current_user_required)],
    ) -> CurrentUser:
        for r in roles:
            if r in user.roles:
                return user

        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Role required: one of {roles}",
        )

    return role_dependency


# ==================== CONVENIENCE DEPENDENCIES ====================


# Pre-configured role dependencies for common use cases
require_admin = require_role("admin")
require_underwriter = require_any_role("admin", "underwriter")
require_broker = require_any_role("admin", "broker")

# Pre-configured permission dependencies for common use cases
require_sui_read = require_permission("sui:read")
require_sui_write = require_permission("sui:write")
require_rules_read = require_permission("rules:read")
require_rules_write = require_permission("rules:write")
require_evaluations_read = require_permission("evaluations:read")
require_evaluations_write = require_permission("evaluations:write")
