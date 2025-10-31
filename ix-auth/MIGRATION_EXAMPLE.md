# Migration Example: Using ix-auth in ix-ds

This document shows how to migrate from the embedded auth code to the ix-auth package.

## Step 1: Install the Package

```bash
cd ../ix-ds
uv add ix-auth --path ../ix-packages/ix-auth
```

## Step 2: Update imports in src/shared/config/__init__.py

**Before (embedded):**
```python
from src.shared.config.auth import AuthSettings

# Settings with hardcoded IX_DS_AUTH_ prefix
auth = AuthSettings()
```

**After (ix-auth package):**
```python
from ix_auth import AuthSettings

# Settings with configurable prefix
auth = AuthSettings.with_prefix("IX_DS_AUTH_")
```

## Step 3: Update middleware in src/api/app.py

**Before:**
```python
from src.api.middleware.auth import AuthMiddleware
from src.shared.config import settings

if settings.auth.enabled:
    app.add_middleware(AuthMiddleware, logger=logger)
```

**After:**
```python
from ix_auth.middleware.fastapi import AuthMiddleware
from src.shared.config import settings
from src.shared.db import admin_db_pool

if settings.auth.enabled:
    app.add_middleware(
        AuthMiddleware,
        settings=settings.auth,
        admin_db_pool=admin_db_pool,
        logger=logger,
    )
```

## Step 4: Update route dependencies

**Before:**
```python
from src.api.dependencies.auth import require_permission, CurrentUser

@router.post("/api/v2/inscoping/suis")
async def create_sui(
    sui: SUIRequest,
    user: CurrentUser = Depends(require_permission("sui:write"))
):
    # ...
```

**After:**
```python
from ix_auth.dependencies.fastapi import require_permission
from ix_auth.models import CurrentUser

@router.post("/api/v2/inscoping/suis")
async def create_sui(
    sui: SUIRequest,
    user: CurrentUser = Depends(require_permission("sui:write"))
):
    # ... (no change in usage!)
```

## Step 5: Update initialization in lifespan

**Before:**
```python
from src.auth.init_data import initialize_roles_and_permissions

async def lifespan(app: FastAPI):
    # ... database setup ...
    await initialize_roles_and_permissions(admin_pool)
    # ...
```

**After:**
```python
from ix_auth import initialize_roles_and_permissions

async def lifespan(app: FastAPI):
    # ... database setup ...
    await initialize_roles_and_permissions(
        admin_pool,
        schema="ix_admin",  # or settings.auth.admin_db_schema
        logger=logger,
    )
    # ...
```

## Step 6: Remove old auth code

After verifying everything works, you can remove:
- `src/auth/` directory
- `src/api/middleware/auth.py`
- `src/api/dependencies/auth.py`
- `src/shared/config/auth.py`

## For fenix-agents

The process is similar, but use a different prefix:

```python
# In fenix-agents
from ix_auth import AuthSettings

# Use FENIX_AUTH_ environment variables
auth_settings = AuthSettings.with_prefix("FENIX_AUTH_")
```

## Benefits of the Migration

1. **No code duplication** - Single source of truth for auth logic
2. **Configurable prefixes** - Each service can use its own env vars
3. **Same functionality** - API is identical, just import paths change
4. **Type-safe** - Full type hints with `py.typed` marker
5. **Well tested** - Comprehensive test suite included
6. **Easy updates** - Update auth logic in one place for all services
