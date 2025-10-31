"""Shared test fixtures and configuration."""

import asyncio
import os
from collections.abc import AsyncGenerator
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock
from uuid import UUID, uuid4

import pytest
import pytest_asyncio
from fastapi import FastAPI
from httpx import AsyncClient

from ix_auth import AuthSettings, CurrentUser, MockAuthProvider
from ix_auth.models import TokenPayload, User
from ix_auth.repositories import UserRepository

# Set test environment variables
os.environ["AUTH_JWT_SECRET"] = "test-secret-key-for-testing-only"
os.environ["AUTH_MOCK_ENABLED"] = "true"
os.environ["AUTH_AZURE_ENABLED"] = "false"


@pytest.fixture(scope="session")
def event_loop():
    """Create an event loop for async tests."""
    loop = asyncio.get_event_loop_policy().new_event_loop()
    yield loop
    loop.close()


@pytest.fixture
def auth_settings() -> AuthSettings:
    """Create test auth settings."""
    return AuthSettings(
        enabled=True,
        jwt_secret="test-secret-key-for-testing-only",
        jwt_algorithm="HS256",
        jwt_expire_minutes=60,
        mock_enabled=True,
        azure_enabled=False,
        admin_db_host="localhost",
        admin_db_port=5432,
        admin_db_name="test_db",
        admin_db_user="test",
        admin_db_password="test",
    )


@pytest.fixture
def mock_provider(auth_settings: AuthSettings) -> MockAuthProvider:
    """Create mock authentication provider."""
    return MockAuthProvider(auth_settings)


@pytest.fixture
def sample_user_id() -> UUID:
    """Generate a sample user ID."""
    return uuid4()


@pytest.fixture
def sample_user(sample_user_id: UUID) -> User:
    """Create a sample user."""
    return User(
        id=sample_user_id,
        email="test@example.com",
        name="Test User",
        is_active=True,
        is_system=False,
        created_at=datetime.now(timezone.utc),
        updated_at=datetime.now(timezone.utc),
    )


@pytest.fixture
def sample_token_payload(sample_user_id: UUID) -> TokenPayload:
    """Create a sample token payload."""
    import time

    return TokenPayload(
        sub=str(sample_user_id),
        exp=int(time.time()) + 3600,
        iat=int(time.time()),
        iss="test",
        user_id=sample_user_id,
        email="test@example.com",
        name="Test User",
        roles=["admin"],
        permissions=["sui:read", "sui:write", "rules:read", "rules:write"],
    )


@pytest.fixture
def current_user(sample_user_id: UUID) -> CurrentUser:
    """Create a current user object."""
    return CurrentUser(
        id=sample_user_id,
        email="test@example.com",
        name="Test User",
        roles=["admin"],
        permissions=["sui:read", "sui:write", "rules:read", "rules:write"],
    )


@pytest.fixture
def mock_db_pool():
    """Create a mock database pool."""
    pool = MagicMock()
    pool.acquire = MagicMock()

    # Create a mock connection context manager
    conn = MagicMock()
    conn.__aenter__ = AsyncMock(return_value=conn)
    conn.__aexit__ = AsyncMock(return_value=None)
    conn.fetchrow = AsyncMock(return_value=None)
    conn.fetch = AsyncMock(return_value=[])
    conn.fetchval = AsyncMock(return_value=None)
    conn.execute = AsyncMock(return_value=None)

    pool.acquire.return_value = conn
    return pool


@pytest.fixture
def user_repository(mock_db_pool):
    """Create a user repository with mocked database."""
    return UserRepository(mock_db_pool, schema="public")


@pytest.fixture
def fastapi_app() -> FastAPI:
    """Create a test FastAPI application."""
    app = FastAPI(title="Test App")
    return app


@pytest_asyncio.fixture
async def async_client(fastapi_app: FastAPI) -> AsyncGenerator[AsyncClient, None]:
    """Create an async test client."""
    async with AsyncClient(app=fastapi_app, base_url="http://test") as client:
        yield client


@pytest.fixture
def mock_request():
    """Create a mock FastAPI request object."""
    request = MagicMock()
    request.state.user = None
    request.state.is_authenticated = False
    request.headers = {"Authorization": "Bearer test-token"}
    request.url.path = "/api/test"
    return request


@pytest.fixture
def authenticated_request(mock_request, sample_token_payload):
    """Create an authenticated mock request."""
    mock_request.state.user = sample_token_payload
    mock_request.state.is_authenticated = True
    return mock_request


@pytest.fixture(autouse=True)
def reset_environment():
    """Reset environment variables after each test."""
    original_env = os.environ.copy()
    yield
    os.environ.clear()
    os.environ.update(original_env)
