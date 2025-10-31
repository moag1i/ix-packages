"""User repository for auth database operations.

Handles CRUD operations for users, roles, and permissions.
"""

from datetime import datetime, timezone
from typing import Any
from uuid import UUID, uuid4

from ..models.db_models import (
    Permission,
    Role,
    User,
)


class UserRepository:
    """
    Repository for user authentication and authorization data.

    Handles operations on:
    - users
    - roles
    - permissions
    - user_roles (many-to-many)
    - role_permissions (many-to-many)
    - auth_logs (audit trail)

    Example usage:
        repo = UserRepository(admin_db_pool, schema="public", logger=logger)

        # Get user by email
        user = await repo.get_user_by_email("john@example.com")

        # Get user with roles
        user, roles = await repo.get_user_with_roles(user_id)

        # Assign role to user
        await repo.assign_role_to_user(user_id, role_id)

        # Check if user has permission
        has_perm = await repo.user_has_permission(user_id, "sui:write")
    """

    def __init__(self, db_pool, schema: str = "public", logger=None):
        """
        Initialize user repository.

        Args:
            db_pool: Database connection pool (ff-storage PostgresPool)
            schema: Database schema for auth tables (default: "public")
            logger: Optional logger instance
        """
        self.db = db_pool
        self.schema = schema
        self.logger = logger

    # ==================== USER OPERATIONS ====================

    async def get_user_by_id(self, user_id: UUID) -> User | None:
        """
        Get user by ID.

        Args:
            user_id: User UUID

        Returns:
            User model or None if not found
        """
        query = f"""
            SELECT * FROM {self.schema}.users
            WHERE id = $1 AND is_active = true
        """

        async with self.db.acquire() as conn:
            row = await conn.fetchrow(query, user_id)
            if row:
                return User(**dict(row))
            return None

    async def get_user_by_email(self, email: str) -> User | None:
        """
        Get user by email.

        Args:
            email: User email address

        Returns:
            User model or None if not found
        """
        query = f"""
            SELECT * FROM {self.schema}.users
            WHERE email = $1 AND is_active = true
        """

        async with self.db.acquire() as conn:
            row = await conn.fetchrow(query, email)
            if row:
                return User(**dict(row))
            return None

    async def get_user_by_azure_oid(self, azure_oid: str) -> User | None:
        """
        Get user by Azure AD Object ID.

        Args:
            azure_oid: Azure AD OID

        Returns:
            User model or None if not found
        """
        query = f"""
            SELECT * FROM {self.schema}.users
            WHERE azure_oid = $1 AND is_active = true
        """

        async with self.db.acquire() as conn:
            row = await conn.fetchrow(query, azure_oid)
            if row:
                return User(**dict(row))
            return None

    async def create_user(self, user: User) -> User:
        """
        Create new user.

        Args:
            user: User model to create

        Returns:
            Created user with database-generated fields
        """
        query = f"""
            INSERT INTO {self.schema}.users
            (id, email, name, azure_oid, tenant_id, tenant_type, is_active, is_system, created_at, updated_at)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $9)
            RETURNING *
        """

        now = datetime.now(timezone.utc)
        if not user.id:
            user.id = uuid4()

        async with self.db.acquire() as conn:
            row = await conn.fetchrow(
                query,
                user.id,
                user.email,
                user.name,
                user.azure_oid,
                user.tenant_id,
                user.tenant_type,
                user.is_active,
                user.is_system,
                now,
            )
            return User(**dict(row))

    async def update_user_last_login(self, user_id: UUID) -> None:
        """
        Update user's last login timestamp.

        Args:
            user_id: User UUID
        """
        query = f"""
            UPDATE {self.schema}.users
            SET last_login = $1, updated_at = $1
            WHERE id = $2
        """

        now = datetime.now(timezone.utc)
        async with self.db.acquire() as conn:
            await conn.execute(query, now, user_id)

    async def deactivate_user(self, user_id: UUID) -> None:
        """
        Deactivate user (soft delete).

        Args:
            user_id: User UUID
        """
        query = f"""
            UPDATE {self.schema}.users
            SET is_active = false, updated_at = $1
            WHERE id = $2 AND is_system = false
        """

        now = datetime.now(timezone.utc)
        async with self.db.acquire() as conn:
            await conn.execute(query, now, user_id)

    # ==================== ROLE OPERATIONS ====================

    async def get_role_by_name(self, name: str) -> Role | None:
        """
        Get role by name.

        Args:
            name: Role name

        Returns:
            Role model or None if not found
        """
        query = f"""
            SELECT * FROM {self.schema}.roles
            WHERE name = $1
        """

        async with self.db.acquire() as conn:
            row = await conn.fetchrow(query, name)
            if row:
                return Role(**dict(row))
            return None

    async def get_all_roles(self) -> list[Role]:
        """
        Get all roles.

        Returns:
            List of all roles
        """
        query = f"""
            SELECT * FROM {self.schema}.roles
            ORDER BY name
        """

        async with self.db.acquire() as conn:
            rows = await conn.fetch(query)
            return [Role(**dict(row)) for row in rows]

    async def get_user_roles(self, user_id: UUID) -> list[Role]:
        """
        Get all roles assigned to a user.

        Args:
            user_id: User UUID

        Returns:
            List of roles
        """
        query = f"""
            SELECT r.* FROM {self.schema}.roles r
            JOIN {self.schema}.user_roles ur ON ur.role_id = r.id
            WHERE ur.user_id = $1
            ORDER BY r.name
        """

        async with self.db.acquire() as conn:
            rows = await conn.fetch(query, user_id)
            return [Role(**dict(row)) for row in rows]

    async def assign_role_to_user(
        self,
        user_id: UUID,
        role_id: UUID,
        assigned_by: UUID | None = None,
    ) -> None:
        """
        Assign role to user.

        Args:
            user_id: User UUID
            role_id: Role UUID
            assigned_by: UUID of user who assigned the role (optional)
        """
        # Check if role already assigned to avoid duplicates
        check_query = f"""
            SELECT id FROM {self.schema}.user_roles
            WHERE user_id = $1 AND role_id = $2
        """

        async with self.db.acquire() as conn:
            existing = await conn.fetchval(check_query, user_id, role_id)
            if existing:
                # Role already assigned
                return

            # Insert new role assignment
            query = f"""
                INSERT INTO {self.schema}.user_roles
                (id, user_id, role_id, assigned_by, assigned_at, created_at, updated_at)
                VALUES ($1, $2, $3, $4, $5, $5, $5)
            """

            now = datetime.now(timezone.utc)
            await conn.execute(query, uuid4(), user_id, role_id, assigned_by, now)

    async def remove_role_from_user(self, user_id: UUID, role_id: UUID) -> None:
        """
        Remove role from user.

        Args:
            user_id: User UUID
            role_id: Role UUID
        """
        query = f"""
            DELETE FROM {self.schema}.user_roles
            WHERE user_id = $1 AND role_id = $2
        """

        async with self.db.acquire() as conn:
            await conn.execute(query, user_id, role_id)

    # ==================== PERMISSION OPERATIONS ====================

    async def get_role_permissions(self, role_id: UUID) -> list[Permission]:
        """
        Get all permissions for a role.

        Args:
            role_id: Role UUID

        Returns:
            List of permissions
        """
        query = f"""
            SELECT p.* FROM {self.schema}.permissions p
            JOIN {self.schema}.role_permissions rp ON rp.permission_id = p.id
            WHERE rp.role_id = $1
            ORDER BY p.resource, p.action
        """

        async with self.db.acquire() as conn:
            rows = await conn.fetch(query, role_id)
            return [Permission(**dict(row)) for row in rows]

    async def get_user_permissions(self, user_id: UUID) -> list[str]:
        """
        Get all permission strings for a user (aggregated from all roles).

        Args:
            user_id: User UUID

        Returns:
            List of permission strings in format "resource:action"
        """
        query = f"""
            SELECT DISTINCT p.resource || ':' || p.action as permission
            FROM {self.schema}.permissions p
            JOIN {self.schema}.role_permissions rp ON rp.permission_id = p.id
            JOIN {self.schema}.user_roles ur ON ur.role_id = rp.role_id
            WHERE ur.user_id = $1
            ORDER BY permission
        """

        async with self.db.acquire() as conn:
            rows = await conn.fetch(query, user_id)
            return [row["permission"] for row in rows]

    async def user_has_permission(self, user_id: UUID, permission: str) -> bool:
        """
        Check if user has a specific permission.

        Args:
            user_id: User UUID
            permission: Permission string in format "resource:action"

        Returns:
            True if user has the permission
        """
        resource, action = permission.split(":", 1)

        query = f"""
            SELECT EXISTS (
                SELECT 1
                FROM {self.schema}.permissions p
                JOIN {self.schema}.role_permissions rp ON rp.permission_id = p.id
                JOIN {self.schema}.user_roles ur ON ur.role_id = rp.role_id
                WHERE ur.user_id = $1
                  AND p.resource = $2
                  AND p.action = $3
            ) as has_permission
        """

        async with self.db.acquire() as conn:
            result = await conn.fetchval(query, user_id, resource, action)
            return bool(result)

    # ==================== AUTH LOGGING ====================

    async def log_auth_event(
        self,
        event_type: str,
        user_id: UUID | None = None,
        event_details: dict[str, Any] | None = None,
        ip_address: str | None = None,
        user_agent: str | None = None,
    ) -> None:
        """
        Log authentication event for audit trail.

        Args:
            event_type: Event type (login, logout, failed_login, etc.)
            user_id: User UUID (None for failed login attempts)
            event_details: Additional event details as dict
            ip_address: Client IP address
            user_agent: Client user agent string
        """
        query = f"""
            INSERT INTO {self.schema}.auth_logs
            (id, user_id, event_type, event_details, ip_address, user_agent, created_at, updated_at)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $7)
        """

        now = datetime.now(timezone.utc)
        async with self.db.acquire() as conn:
            await conn.execute(
                query,
                uuid4(),
                user_id,
                event_type,
                event_details,
                ip_address,
                user_agent,
                now,
            )

    # ==================== COMBINED OPERATIONS ====================

    async def get_user_with_roles_and_permissions(
        self, user_id: UUID
    ) -> tuple[User | None, list[str], list[str]]:
        """
        Get user with their roles and permissions in one query.

        Args:
            user_id: User UUID

        Returns:
            Tuple of (user, role_names, permission_strings)
        """
        user = await self.get_user_by_id(user_id)
        if not user:
            return None, [], []

        roles = await self.get_user_roles(user_id)
        role_names = [role.name for role in roles]

        permissions = await self.get_user_permissions(user_id)

        return user, role_names, permissions
