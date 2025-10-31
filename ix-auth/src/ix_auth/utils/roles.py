"""Role and permission initialization utilities."""

from ff_storage.pydantic_support import PydanticRepository

from ..models.db_models import Permission, Role, RolePermission

# Default system roles
DEFAULT_ROLES = [
    {
        "name": "admin",
        "description": "Full system administrator access",
        "is_system": True,
    },
    {
        "name": "underwriter",
        "description": "Can manage rules and view/evaluate SUIs",
        "is_system": True,
    },
    {
        "name": "broker",
        "description": "Can manage SUIs and view rules",
        "is_system": True,
    },
    {
        "name": "viewer",
        "description": "Read-only access to all resources",
        "is_system": True,
    },
]

# Default permissions (resource, action, description)
DEFAULT_PERMISSIONS: list[tuple[str, str, str]] = [
    ("sui", "read", "View submission underwriting info"),
    ("sui", "write", "Create and modify submission underwriting info"),
    ("rules", "read", "View underwriting rules"),
    ("rules", "write", "Create and modify underwriting rules"),
    ("evaluations", "read", "View rule evaluation results"),
    ("evaluations", "write", "Execute rule evaluations"),
    ("admin", "read", "View administrative data"),
    ("admin", "write", "Modify administrative data"),
]

# Role-permission mappings
ROLE_PERMISSIONS: dict[str, list[str]] = {
    "admin": [
        "sui:read",
        "sui:write",
        "rules:read",
        "rules:write",
        "evaluations:read",
        "evaluations:write",
        "admin:read",
        "admin:write",
    ],
    "underwriter": [
        "sui:read",
        "rules:read",
        "rules:write",
        "evaluations:read",
        "evaluations:write",
    ],
    "broker": [
        "sui:read",
        "sui:write",
        "rules:read",
        "evaluations:read",
    ],
    "viewer": [
        "sui:read",
        "rules:read",
        "evaluations:read",
        "admin:read",
    ],
}


async def initialize_roles_and_permissions(
    db_pool,
    schema: str = "public",
    logger=None,
) -> None:
    """
    Initialize default roles and permissions.

    Creates system roles (admin, underwriter, broker, viewer) and
    permissions, then assigns permissions to roles.

    This is idempotent - safe to run multiple times.

    Args:
        db_pool: Database connection pool (ff-storage PostgresPool)
        schema: Database schema for auth tables (default: "public")
        logger: Optional logger instance
    """
    if logger:
        logger.info("Initializing roles and permissions", schema=schema)

    # Update model schemas if needed
    if schema != "public":
        Role.__schema__ = schema
        Permission.__schema__ = schema
        RolePermission.__schema__ = schema

    # Create PydanticRepository instances for CRUD operations
    role_repo = PydanticRepository(
        model_class=Role,
        db_pool=db_pool,
        tenant_id=None,
        logger=logger,
    )
    perm_repo = PydanticRepository(
        model_class=Permission,
        db_pool=db_pool,
        tenant_id=None,
        logger=logger,
    )
    role_perm_repo = PydanticRepository(
        model_class=RolePermission,
        db_pool=db_pool,
        tenant_id=None,
        logger=logger,
    )

    try:
        # Create roles (skip if already exist)
        created_roles = {}
        for role_data in DEFAULT_ROLES:
            # Check if role exists
            query = f"""
                SELECT * FROM {schema}.roles
                WHERE name = $1
                LIMIT 1
            """
            async with db_pool.acquire() as conn:
                existing = await conn.fetchrow(query, role_data["name"])

            if existing:
                if logger:
                    logger.info(f"Role '{role_data['name']}' already exists, skipping")
                created_roles[role_data["name"]] = Role(**dict(existing))
            else:
                # Create role using PydanticRepository
                role = Role(**role_data)
                created_role = await role_repo.create(role)
                created_roles[role_data["name"]] = created_role
                if logger:
                    logger.info(f"Created role: {role_data['name']}")

        # Create permissions (skip if already exist)
        created_permissions = {}
        for resource, action, description in DEFAULT_PERMISSIONS:
            perm_key = f"{resource}:{action}"

            # Check if permission exists
            query = f"""
                SELECT * FROM {schema}.permissions
                WHERE resource = $1 AND action = $2
                LIMIT 1
            """
            async with db_pool.acquire() as conn:
                existing = await conn.fetchrow(query, resource, action)

            if existing:
                if logger:
                    logger.info(f"Permission '{perm_key}' already exists, skipping")
                created_permissions[perm_key] = Permission(**dict(existing))
            else:
                # Create permission using PydanticRepository
                permission = Permission(
                    resource=resource,
                    action=action,
                    description=description,
                )
                created_perm = await perm_repo.create(permission)
                created_permissions[perm_key] = created_perm
                if logger:
                    logger.info(f"Created permission: {perm_key}")

        # Assign permissions to roles
        for role_name, permissions in ROLE_PERMISSIONS.items():
            role = created_roles[role_name]

            for perm_key in permissions:
                permission = created_permissions[perm_key]

                # Check if already assigned
                query = f"""
                    SELECT * FROM {schema}.role_permissions
                    WHERE role_id = $1 AND permission_id = $2
                    LIMIT 1
                """
                async with db_pool.acquire() as conn:
                    existing = await conn.fetchrow(query, role.id, permission.id)

                if existing:
                    continue

                # Assign permission to role using PydanticRepository
                role_permission = RolePermission(
                    role_id=role.id,
                    permission_id=permission.id,
                )
                await role_perm_repo.create(role_permission)

            if logger:
                logger.info(f"Assigned {len(permissions)} permissions to role '{role_name}'")

        if logger:
            logger.info("Roles and permissions initialization complete")

    except Exception as e:
        if logger:
            logger.error(
                "Failed to initialize roles and permissions",
                error=str(e),
                exc_info=True,
            )
        raise


def get_role_permissions(role: str) -> list[str]:
    """
    Get the default permissions for a role.

    Args:
        role: Role name (e.g., "admin", "underwriter")

    Returns:
        List of permission strings in "resource:action" format
    """
    return ROLE_PERMISSIONS.get(role.lower(), [])


def get_all_permissions() -> list[tuple[str, str, str]]:
    """
    Get all default permissions.

    Returns:
        List of tuples: (resource, action, description)
    """
    return DEFAULT_PERMISSIONS


def get_all_roles() -> list[dict[str, any]]:
    """
    Get all default roles.

    Returns:
        List of role dictionaries with name, description, and is_system
    """
    return DEFAULT_ROLES
