"""Role and permission initialization utilities."""

from uuid import uuid4

from ff_storage.pydantic_support import PydanticRepository

from ..models.db_models import AzureTenantMapping, Permission, Role, RolePermission

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
    schema: str = "ix_admin",
    logger=None,
) -> None:
    """
    Initialize default roles and permissions.

    Creates system roles (admin, underwriter, broker, viewer) and
    permissions, then assigns permissions to roles.

    This is idempotent - safe to run multiple times.

    Args:
        db_pool: Database connection pool (ff-storage PostgresPool)
        schema: Database schema for auth tables (default: "ix_admin")
        logger: Optional logger instance
    """
    if logger:
        logger.info("Initializing roles and permissions", schema=schema)

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


async def initialize_tenant_mappings(
    db_pool,
    azure_tenant_id: str,
    insurx_tenant_id: str,
    schema: str = "ix_admin",
    logger=None,
) -> None:
    """
    Initialize default Azure tenant mapping for InsurX.

    Creates a mapping from the InsurX Azure AD tenant to the InsurX platform tenant.
    This is idempotent - safe to run multiple times.

    Args:
        db_pool: Database connection pool (ff-storage PostgresPool)
        azure_tenant_id: Azure AD tenant ID (from Azure)
        insurx_tenant_id: InsurX internal tenant ID
        schema: Database schema for auth tables (default: "ix_admin")
        logger: Optional logger instance
    """
    if logger:
        logger.info(
            "Initializing tenant mappings",
            schema=schema,
            azure_tenant_id=azure_tenant_id,
        )

    try:
        # Create repository
        tenant_mapping_repo = PydanticRepository(
            model_class=AzureTenantMapping,
            db_pool=db_pool,
            tenant_id=None,  # Auth is global
            logger=logger,
        )

        # Check if mapping already exists
        existing = await tenant_mapping_repo.list(
            filters={"azure_tenant_id": azure_tenant_id},
            limit=1,
        )

        if existing:
            if logger:
                logger.info(
                    "Tenant mapping already exists, skipping",
                    azure_tenant_id=azure_tenant_id,
                )
            return

        # Create InsurX tenant mapping
        mapping = AzureTenantMapping(
            id=uuid4(),
            azure_tenant_id=azure_tenant_id,
            insurx_tenant_id=insurx_tenant_id,
            tenant_name="InsurX Exchange",
            tenant_type="admin",  # InsurX is the exchange/admin, not a broker
            is_active=True,
        )

        await tenant_mapping_repo.create(mapping)

        if logger:
            logger.info(
                "Created tenant mapping",
                azure_tenant_id=azure_tenant_id,
                insurx_tenant_id=insurx_tenant_id,
                tenant_type="admin",
            )

        if logger:
            logger.info("Tenant mapping initialization complete")

    except Exception as e:
        if logger:
            logger.error(
                "Failed to initialize tenant mappings",
                error=str(e),
                exc_info=True,
            )
        raise
