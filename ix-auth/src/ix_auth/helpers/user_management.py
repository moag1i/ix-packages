"""User management helper functions using ff-storage v3 patterns.

Provides centralized, reusable user management logic that follows
the platform's PydanticRepository pattern.

These functions can be used across all services and overridden if needed.
"""

from datetime import datetime, timezone
from typing import List, Optional
from uuid import UUID, uuid4

from ff_storage.pydantic_support import PydanticRepository

from ..models import AuthLog, Permission, Role, User, UserRole, UserWithRoles


async def provision_user_from_azure(
    user_repo: PydanticRepository,
    role_repo: PydanticRepository,
    user_role_repo: PydanticRepository,
    user_info: dict,
    default_role: str = "viewer",
    logger=None,
) -> User:
    """
    Provision user from Azure AD information.

    Creates user if doesn't exist, or updates last login if exists.
    Assigns default role to new users.

    Args:
        user_repo: PydanticRepository for User model
        role_repo: PydanticRepository for Role model
        user_role_repo: PydanticRepository for UserRole model
        user_info: Azure user info dict with keys:
            - email: str (or mail, or userPrincipalName)
            - name: str (or displayName)
            - oid: str (Azure object ID)
            - tid: str (Azure tenant ID)
        default_role: Default role name for new users (default: "viewer")
        logger: Optional logger instance

    Returns:
        User: Provisioned user

    Example:
        ```python
        user = await provision_user_from_azure(
            user_repo=user_repo,
            role_repo=role_repo,
            user_role_repo=user_role_repo,
            user_info=azure_user_info,
            default_role="viewer",
            logger=logger,
        )
        ```
    """
    # Extract user info from Azure response
    email = user_info.get("email") or user_info.get("mail") or user_info.get("userPrincipalName")
    name = user_info.get("name") or user_info.get("displayName") or email
    azure_oid = user_info.get("oid") or user_info.get("id")
    azure_tid = user_info.get("tid")

    if not email or not azure_oid:
        raise ValueError("Azure user info must contain email and oid")

    # Try to find existing user by Azure OID
    existing_users = await user_repo.list(filters={"azure_oid": azure_oid}, limit=1)

    if existing_users:
        user = existing_users[0]
        # Update last login
        user.last_login = datetime.now(timezone.utc)
        await user_repo.update(user.id, user)

        if logger:
            logger.info(
                "User logged in",
                user_id=str(user.id),
                email=user.email,
            )
        return user

    # Try to find by email (in case user was created without Azure OID)
    existing_users = await user_repo.list(filters={"email": email}, limit=1)

    if existing_users:
        user = existing_users[0]
        # Update with Azure OID and last login
        user.azure_oid = azure_oid
        user.last_login = datetime.now(timezone.utc)
        await user_repo.update(user.id, user)

        if logger:
            logger.info(
                "User logged in (linked Azure account)",
                user_id=str(user.id),
                email=user.email,
                azure_oid=azure_oid,
            )
        return user

    # Create new user
    new_user = User(
        id=uuid4(),
        email=email,
        name=name,
        azure_oid=azure_oid,
        is_active=True,
        is_system=False,
        last_login=datetime.now(timezone.utc),
    )

    created_user = await user_repo.create(new_user)

    # Assign default role to new user
    default_roles = await role_repo.list(filters={"name": default_role}, limit=1)
    if default_roles:
        user_role = UserRole(
            id=uuid4(),
            user_id=created_user.id,
            role_id=default_roles[0].id,
            assigned_by=created_user.id,  # Self-assigned
            assigned_at=datetime.now(timezone.utc),
        )
        await user_role_repo.create(user_role)

        if logger:
            logger.info(
                "Assigned default role to new user",
                user_id=str(created_user.id),
                role=default_role,
            )

    if logger:
        logger.info(
            "New user provisioned from Azure AD",
            user_id=str(created_user.id),
            email=created_user.email,
            azure_oid=azure_oid,
        )

    return created_user


async def get_user_with_roles_and_permissions(
    user_repo: PydanticRepository,
    user_id: UUID,
    db_pool,
    schema: str = "ix_admin",
    logger=None,
) -> Optional[UserWithRoles]:
    """
    Get user with their assigned roles and permissions.

    Uses raw SQL for the JOIN query (no PydanticRepository equivalent).

    Args:
        user_repo: PydanticRepository for User model
        user_id: User UUID
        db_pool: Database connection pool for raw queries
        schema: Database schema (default: "ix_admin")
        logger: Optional logger instance

    Returns:
        UserWithRoles: User with roles and permissions, or None if not found

    Example:
        ```python
        user_with_roles = await get_user_with_roles_and_permissions(
            user_repo=user_repo,
            user_id=user_id,
            db_pool=admin_pool,
            schema="ix_admin",
        )
        ```
    """
    # Get user
    users = await user_repo.list(filters={"id": user_id, "is_active": True}, limit=1)
    if not users:
        return None

    user = users[0]

    # Get roles and permissions via JOIN (complex query - use raw SQL)
    query = f"""
        SELECT
            r.name as role_name,
            p.resource || ':' || p.action as permission
        FROM {schema}.user_roles ur
        JOIN {schema}.roles r ON r.id = ur.role_id
        LEFT JOIN {schema}.role_permissions rp ON rp.role_id = r.id
        LEFT JOIN {schema}.permissions p ON p.id = rp.permission_id
        WHERE ur.user_id = $1
    """

    async with db_pool.acquire() as conn:
        rows = await conn.fetch(query, user_id)

    # Extract unique roles and permissions
    roles = list(set(row["role_name"] for row in rows if row["role_name"]))
    permissions = list(set(row["permission"] for row in rows if row["permission"]))

    return UserWithRoles(
        id=user.id,
        email=user.email,
        name=user.name,
        azure_oid=user.azure_oid,
        tenant_id=user.tenant_id,
        tenant_type=user.tenant_type,
        is_active=user.is_active,
        roles=roles,
        permissions=permissions,
    )


async def assign_role_to_user(
    user_role_repo: PydanticRepository,
    user_id: UUID,
    role_id: UUID,
    assigned_by: UUID,
    logger=None,
) -> UserRole:
    """
    Assign a role to a user.

    Args:
        user_role_repo: PydanticRepository for UserRole model
        user_id: User UUID
        role_id: Role UUID
        assigned_by: UUID of user performing the assignment
        logger: Optional logger instance

    Returns:
        UserRole: Created user-role association

    Example:
        ```python
        user_role = await assign_role_to_user(
            user_role_repo=user_role_repo,
            user_id=user.id,
            role_id=admin_role.id,
            assigned_by=current_user.id,
        )
        ```
    """
    # Check if already assigned
    existing = await user_role_repo.list(
        filters={"user_id": user_id, "role_id": role_id},
        limit=1
    )

    if existing:
        if logger:
            logger.warning(
                "Role already assigned to user",
                user_id=str(user_id),
                role_id=str(role_id),
            )
        return existing[0]

    # Create new assignment
    user_role = UserRole(
        id=uuid4(),
        user_id=user_id,
        role_id=role_id,
        assigned_by=assigned_by,
        assigned_at=datetime.now(timezone.utc),
    )

    created = await user_role_repo.create(user_role)

    if logger:
        logger.info(
            "Role assigned to user",
            user_id=str(user_id),
            role_id=str(role_id),
            assigned_by=str(assigned_by),
        )

    return created


async def log_auth_event(
    auth_log_repo: PydanticRepository,
    user_id: UUID,
    event_type: str,
    ip_address: Optional[str] = None,
    user_agent: Optional[str] = None,
    details: Optional[dict] = None,
    logger=None,
) -> AuthLog:
    """
    Log authentication event.

    Args:
        auth_log_repo: PydanticRepository for AuthLog model
        user_id: User UUID
        event_type: Event type (e.g., "login", "logout", "password_change")
        ip_address: Optional IP address
        user_agent: Optional user agent string
        details: Optional additional event details
        logger: Optional logger instance

    Returns:
        AuthLog: Created auth log entry

    Example:
        ```python
        await log_auth_event(
            auth_log_repo=auth_log_repo,
            user_id=user.id,
            event_type="login",
            ip_address="192.168.1.1",
            user_agent="Mozilla/5.0...",
        )
        ```
    """
    event_details = details or {}
    if ip_address and "ip_address" not in event_details:
        event_details["ip_address"] = ip_address
    if user_agent and "user_agent" not in event_details:
        event_details["user_agent"] = user_agent

    auth_log = AuthLog(
        id=uuid4(),
        user_id=user_id,
        event_type=event_type,
        event_details=event_details,
        ip_address=ip_address,
        user_agent=user_agent,
        created_at=datetime.now(timezone.utc),
    )

    created = await auth_log_repo.create(auth_log)

    if logger:
        logger.info(
            "Auth event logged",
            user_id=str(user_id),
            event_type=event_type,
            ip_address=ip_address,
        )

    return created