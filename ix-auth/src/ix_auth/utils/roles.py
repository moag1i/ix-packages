"""Role and permission initialization utilities."""

from uuid import uuid4

from ff_storage.pydantic_support import PydanticRepository

from ..models.db_models import AzureTenantMapping, Permission, Role, RolePermission
from ..models.role_config import RolePermissionConfig


async def initialize_roles_and_permissions(
    db_pool,
    config: RolePermissionConfig,
    schema: str = "ix_admin",
    logger=None,
) -> None:
    """
    Initialize roles and permissions from provided configuration.

    Creates roles and permissions based on the service-specific configuration,
    then assigns permissions to roles. This is idempotent - safe to run multiple times.

    Args:
        db_pool: Database connection pool (ff-storage PostgresPool)
        config: Role and permission configuration (REQUIRED)
        schema: Database schema for auth tables (default: "ix_admin")
        logger: Optional logger instance

    Raises:
        ValueError: If config validation fails
        Exception: If database operations fail
    """
    # Validate configuration
    config.validate_role_permissions_exist()

    if logger:
        logger.info(
            f"Initializing roles and permissions for service: {config.service_name}",
            schema=schema,
            num_roles=len(config.roles),
            num_permissions=len(config.permissions),
        )

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
        # Create permissions (skip if already exist)
        created_permissions = {}
        for perm_config in config.permissions:
            perm_key = perm_config.name

            # Check if permission exists
            query = f"""
                SELECT * FROM {schema}.permissions
                WHERE resource = $1 AND action = $2
                LIMIT 1
            """
            async with db_pool.acquire() as conn:
                existing = await conn.fetchrow(query, perm_config.resource, perm_config.action)

            if existing:
                if logger:
                    logger.info(f"Permission '{perm_key}' already exists, skipping")
                created_permissions[perm_key] = Permission(**dict(existing))
            else:
                # Create permission using PydanticRepository
                permission = Permission(
                    resource=perm_config.resource,
                    action=perm_config.action,
                    description=perm_config.description,
                )
                created_perm = await perm_repo.create(permission)
                created_permissions[perm_key] = created_perm
                if logger:
                    logger.info(f"Created permission: {perm_key}")

        # Create roles (skip if already exist)
        created_roles = {}
        for role_config in config.roles:
            # Check if role exists
            query = f"""
                SELECT * FROM {schema}.roles
                WHERE name = $1
                LIMIT 1
            """
            async with db_pool.acquire() as conn:
                existing = await conn.fetchrow(query, role_config.name)

            if existing:
                if logger:
                    logger.info(f"Role '{role_config.name}' already exists, skipping")
                created_roles[role_config.name] = Role(**dict(existing))
            else:
                # Create role using PydanticRepository
                role = Role(
                    name=role_config.name,
                    description=role_config.description,
                    is_system=role_config.is_system,
                )
                created_role = await role_repo.create(role)
                created_roles[role_config.name] = created_role
                if logger:
                    logger.info(f"Created role: {role_config.name}")

        # Assign permissions to roles
        role_perms_map = config.get_role_permissions_map()
        for role_name, permission_names in role_perms_map.items():
            role = created_roles[role_name]

            assigned_count = 0
            for perm_key in permission_names:
                if perm_key not in created_permissions:
                    if logger:
                        logger.warning(
                            f"Permission '{perm_key}' not found for role '{role_name}', skipping"
                        )
                    continue

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
                assigned_count += 1

            if logger and assigned_count > 0:
                logger.info(f"Assigned {assigned_count} new permissions to role '{role_name}'")

        if logger:
            logger.info(f"Roles and permissions initialization complete for {config.service_name}")

    except Exception as e:
        if logger:
            logger.error(
                f"Failed to initialize roles and permissions for {config.service_name}",
                error=str(e),
                exc_info=True,
            )
        raise


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
