"""Authentication middleware for FastAPI.

Handles JWT token validation and user context injection into requests.
"""

import time
from uuid import UUID

import jwt
from fastapi import Request
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse

from ..config import AuthSettings
from ..models import TokenPayload
from ..providers import AzureADProvider, MockAuthProvider
from ..repositories import UserRepository


class AuthMiddleware(BaseHTTPMiddleware):
    """
    Authentication middleware for FastAPI.

    Validates JWT tokens and injects user context into request state.
    Skips authentication for public endpoints (health, docs, auth).

    Example usage:
        from ix_auth import AuthSettings
        from ix_auth.middleware.fastapi import AuthMiddleware

        settings = AuthSettings.with_prefix("IX_DS_AUTH_")

        app.add_middleware(
            AuthMiddleware,
            settings=settings,
            admin_db_pool=admin_db_pool,
            logger=logger,
        )

    The middleware adds to request.state:
    - request.state.user: TokenPayload with user info
    - request.state.is_authenticated: bool

    Public endpoints (no auth required):
    - /health
    - /docs, /redoc, /openapi.json
    - /auth/* (login, callback, etc.)
    """

    # Default paths that don't require authentication
    DEFAULT_PUBLIC_PATHS = {
        "/health",
        "/docs",
        "/redoc",
        "/openapi.json",
        "/auth/health",
        "/auth/login",
        "/auth/callback",
        "/auth/token",
        "/auth/mock-token",
    }

    # Default path prefixes that don't require authentication
    DEFAULT_PUBLIC_PREFIXES = []

    def __init__(
        self,
        app,
        settings: AuthSettings,
        admin_db_pool=None,
        logger=None,
        public_paths: set | None = None,
        public_prefixes: list | None = None,
    ):
        """
        Initialize auth middleware.

        Args:
            app: FastAPI application
            settings: Authentication settings
            admin_db_pool: Optional database pool for user repository
            logger: Optional logger instance
            public_paths: Optional set of exact paths that don't require auth
            public_prefixes: Optional list of path prefixes that don't require auth
        """
        super().__init__(app)
        self.settings = settings
        self.logger = logger

        # Initialize providers based on settings
        self.mock_provider = None
        self.azure_provider = None

        if settings.mock_enabled:
            self.mock_provider = MockAuthProvider(settings)

        if settings.azure_enabled:
            self.azure_provider = AzureADProvider(settings)

        # Initialize user repository if db pool provided
        self.user_repo = None
        if admin_db_pool:
            self.user_repo = UserRepository(
                admin_db_pool,
                schema=settings.admin_db_schema,
                logger=logger,
            )

        # Configure public paths
        self.public_paths = public_paths or self.DEFAULT_PUBLIC_PATHS.copy()
        self.public_prefixes = public_prefixes or self.DEFAULT_PUBLIC_PREFIXES.copy()

    async def dispatch(self, request: Request, call_next):
        """
        Process request through auth middleware.

        Args:
            request: FastAPI request
            call_next: Next middleware/route handler

        Returns:
            Response from next handler or auth error response
        """
        # Initialize request state
        request.state.user = None
        request.state.is_authenticated = False

        # Skip auth if disabled
        if not self.settings.enabled:
            # When auth is disabled, provide default admin user
            request.state.user = self._get_default_user()
            request.state.is_authenticated = True
            return await call_next(request)

        # Check if path is public
        if self._is_public_path(request.url.path):
            return await call_next(request)

        # Extract token from Authorization header
        auth_header = request.headers.get("Authorization")
        if not auth_header:
            # No auth header - continue without authentication
            # Endpoints requiring auth will fail at dependency level
            return await call_next(request)

        # Parse token
        try:
            token = self._extract_token(auth_header)
            if not token:
                return self._auth_error("Invalid authorization header format")

            # Validate token
            payload = await self._validate_token(token)

            # Inject user context into request
            request.state.user = payload
            request.state.is_authenticated = True

            # Continue to next handler
            response = await call_next(request)
            return response

        except jwt.ExpiredSignatureError:
            return self._auth_error("Token has expired", status_code=401)
        except jwt.InvalidTokenError as e:
            return self._auth_error(f"Invalid token: {str(e)}", status_code=401)
        except Exception as e:
            if self.logger:
                self.logger.error("Auth middleware error", error=str(e), exc_info=True)
            return self._auth_error("Authentication error", status_code=500)

    def _is_public_path(self, path: str) -> bool:
        """
        Check if path is public (doesn't require auth).

        Args:
            path: Request path

        Returns:
            True if path is public
        """
        # Check exact matches
        if path in self.public_paths:
            return True

        # Check prefixes
        for prefix in self.public_prefixes:
            if path.startswith(prefix):
                return True

        return False

    def _extract_token(self, auth_header: str) -> str | None:
        """
        Extract JWT token from Authorization header.

        Args:
            auth_header: Authorization header value

        Returns:
            JWT token string or None if invalid format
        """
        parts = auth_header.split()
        if len(parts) != 2 or parts[0].lower() != "bearer":
            return None
        return parts[1]

    async def _validate_token(self, token: str) -> TokenPayload:
        """
        Validate JWT token using appropriate provider.

        Args:
            token: JWT token string

        Returns:
            TokenPayload with decoded claims

        Raises:
            jwt.InvalidTokenError: If token is invalid
        """
        # Try mock provider first (for development)
        if self.mock_provider:
            try:
                return await self.mock_provider.validate_token(token)
            except jwt.InvalidTokenError:
                # If mock validation fails and Azure is enabled, try Azure
                if not self.azure_provider:
                    raise

        # Try Azure AD provider
        if self.azure_provider:
            return await self.azure_provider.validate_token(token)

        # No providers available
        raise jwt.InvalidTokenError("No authentication providers configured")

    def _get_default_user(self) -> TokenPayload:
        """
        Get default admin user when auth is disabled.

        Returns:
            TokenPayload with admin permissions
        """
        return TokenPayload(
            sub="system",
            exp=int(time.time()) + 86400,  # 24 hours
            iat=int(time.time()),
            iss="system",
            user_id=UUID("00000000-0000-0000-0000-000000000000"),
            email="system@insurx.com",
            name="System Admin",
            roles=["admin"],
            permissions=[
                "sui:read",
                "sui:write",
                "rules:read",
                "rules:write",
                "evaluations:read",
                "evaluations:write",
                "admin:read",
                "admin:write",
            ],
        )

    def _auth_error(self, message: str, status_code: int = 401) -> JSONResponse:
        """
        Create auth error response.

        Args:
            message: Error message
            status_code: HTTP status code

        Returns:
            JSON error response
        """
        return JSONResponse(
            status_code=status_code,
            content={"detail": message},
        )
