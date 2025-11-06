"""Authentication configuration settings."""

from typing import TypeVar

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict

T = TypeVar("T", bound="AuthSettings")


class AuthSettings(BaseSettings):
    """
    Authentication and authorization settings with configurable environment prefix.

    Configuration precedence (highest to lowest):
    1. Environment variables ({PREFIX}*)
    2. .env file
    3. Default values

    Example usage:
        # For InsurX (uses IX_DS_AUTH_* environment variables)
        settings = AuthSettings.with_prefix("IX_DS_AUTH_")

        # For fenix-agents (uses FENIX_AUTH_* environment variables)
        settings = AuthSettings.with_prefix("FENIX_AUTH_")

        # Default (uses AUTH_* environment variables)
        settings = AuthSettings()

    Example .env file:
        # Enable/disable auth
        IX_DS_AUTH_ENABLED=true

        # JWT settings
        IX_DS_AUTH_JWT_SECRET=your-secret-key-here
        IX_DS_AUTH_JWT_ALGORITHM=HS256
        IX_DS_AUTH_JWT_EXPIRE_MINUTES=60

        # Azure AD settings
        IX_DS_AUTH_AZURE_TENANT_ID=your-tenant-id
        IX_DS_AUTH_AZURE_CLIENT_ID=your-client-id
        IX_DS_AUTH_AZURE_CLIENT_SECRET=your-client-secret
        IX_DS_AUTH_AZURE_REDIRECT_URI=http://localhost:8000/auth/callback
        IX_DS_AUTH_FRONTEND_URL=http://localhost:3000

        # Mock auth settings (development)
        IX_DS_AUTH_MOCK_ENABLED=true
        IX_DS_AUTH_MOCK_USER_EMAIL=dev@insurx.com
        IX_DS_AUTH_MOCK_USER_NAME=Dev User
        IX_DS_AUTH_MOCK_DEFAULT_ROLE=admin

        # Admin database
        IX_DS_AUTH_ADMIN_DB_HOST=localhost
        IX_DS_AUTH_ADMIN_DB_PORT=5432
        IX_DS_AUTH_ADMIN_DB_NAME=ix_admin
        IX_DS_AUTH_ADMIN_DB_USER=postgres
        IX_DS_AUTH_ADMIN_DB_PASSWORD=postgres
        IX_DS_AUTH_ADMIN_DB_SCHEMA=public
    """

    model_config = SettingsConfigDict(
        env_prefix="AUTH_",  # Default prefix, can be overridden
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # ==================== GENERAL AUTH SETTINGS ====================

    enabled: bool = Field(
        default=False,
        description="Enable authentication. If false, all requests use default admin user.",
    )

    default_role: str = Field(
        default="viewer",
        description="Default role for new users. Options: admin, underwriter, broker, viewer",
    )

    fallback_role: str = Field(
        default="viewer",
        description="Fallback role if user has no roles assigned. Options: admin, underwriter, broker, viewer",
    )

    # ==================== JWT SETTINGS ====================

    jwt_secret: str = Field(
        default="change-this-secret-in-production",
        description="Secret key for signing JWT tokens. MUST be changed in production!",
    )

    jwt_algorithm: str = Field(
        default="HS256",
        description="JWT signing algorithm. Options: HS256, RS256",
    )

    jwt_expire_minutes: int = Field(
        default=60,
        description="JWT token expiration time in minutes",
        ge=5,
        le=1440,  # Max 24 hours
    )

    jwt_refresh_expire_days: int = Field(
        default=7,
        description="Refresh token expiration time in days",
        ge=1,
        le=90,
    )

    # ==================== AZURE AD SETTINGS ====================

    azure_enabled: bool = Field(
        default=False,
        description="Enable Azure AD authentication",
    )

    azure_tenant_id: str = Field(
        default="",
        description="Azure AD Tenant ID",
    )

    azure_client_id: str = Field(
        default="",
        description="Azure AD Application (client) ID",
    )

    azure_client_secret: str = Field(
        default="",
        description="Azure AD Client Secret",
    )

    azure_redirect_uri: str = Field(
        default="http://localhost:8000/auth/callback",
        description="OAuth redirect URI (must match Azure AD app registration)",
    )

    azure_authority: str | None = Field(
        default=None,
        description="Azure AD authority URL. If not set, will be constructed from tenant_id",
    )

    azure_scopes: list[str] = Field(
        default=["openid", "profile", "email", "User.Read"],
        description="Azure AD OAuth scopes (openid, profile, email required for ID token claims)",
    )

    # ==================== MULTI-TENANT SUPPORT ====================

    allow_any_azure_tenant: bool = Field(
        default=False,
        description="Allow JWT tokens from any Azure AD tenant (not just InsurX tenant). "
        "When enabled, removes hardcoded issuer validation. Secure by default (false).",
    )

    auto_register_tenants: bool = Field(
        default=False,
        description="Automatically register new Azure AD tenants on first login. "
        "When disabled, unmapped tenants are blocked. Secure by default (false).",
    )

    auto_register_default_role: str = Field(
        default="viewer",
        description="Default role for auto-registered tenants (most restrictive). "
        "Options: admin, underwriter, broker, viewer",
    )

    frontend_url: str = Field(
        default="http://localhost:3000",
        description="Frontend application URL for OAuth redirects after authentication",
    )

    # ==================== MOCK AUTH SETTINGS (DEVELOPMENT) ====================

    mock_enabled: bool = Field(
        default=True,
        description="Enable mock authentication for development (bypasses Azure AD)",
    )

    mock_user_email: str = Field(
        default="dev@insurx.com",
        description="Default email for mock authentication",
    )

    mock_user_name: str = Field(
        default="Dev User",
        description="Default name for mock authentication",
    )

    mock_user_id: str = Field(
        default="00000000-0000-0000-0000-000000000001",
        description="Default user ID for mock authentication",
    )

    mock_default_role: str = Field(
        default="admin",
        description="Default role for mock authentication. Options: admin, underwriter, broker, viewer",
    )

    # ==================== ADMIN DATABASE SETTINGS ====================

    admin_db_host: str = Field(
        default="localhost",
        description="Admin database host",
    )

    admin_db_port: int = Field(
        default=5432,
        description="Admin database port",
        ge=1,
        le=65535,
    )

    admin_db_name: str = Field(
        default="ix_admin",
        description="Admin database name",
    )

    admin_db_user: str = Field(
        default="postgres",
        description="Admin database user",
    )

    admin_db_password: str = Field(
        default="postgres",
        description="Admin database password",
    )

    admin_db_schema: str = Field(
        default="ix_admin",
        description="Database schema for auth tables",
    )

    admin_db_pool_size: int = Field(
        default=5,
        description="Admin database connection pool size",
        ge=1,
        le=50,
    )

    admin_db_max_overflow: int = Field(
        default=10,
        description="Admin database max overflow connections",
        ge=0,
        le=50,
    )

    # ==================== CLASS METHODS ====================

    @classmethod
    def with_prefix(cls: type[T], prefix: str) -> T:
        """
        Create settings instance with custom environment prefix.

        This allows different services to use different environment variable prefixes
        for their authentication settings.

        Args:
            prefix: Environment variable prefix (e.g., "IX_DS_AUTH_", "FENIX_AUTH_")

        Returns:
            AuthSettings instance configured with the specified prefix

        Example:
            # For InsurX (uses IX_DS_AUTH_*)
            settings = AuthSettings.with_prefix("IX_DS_AUTH_")

            # For fenix-agents (uses FENIX_AUTH_*)
            settings = AuthSettings.with_prefix("FENIX_AUTH_")
        """

        # Create a new class with custom config
        class _PrefixedSettings(cls):
            model_config = SettingsConfigDict(
                env_prefix=prefix,
                env_file=".env",
                env_file_encoding="utf-8",
                case_sensitive=False,
                extra="ignore",
            )

        return _PrefixedSettings()

    # ==================== COMPUTED PROPERTIES ====================

    @property
    def admin_db_url(self) -> str:
        """
        Get admin database URL.

        Returns:
            PostgreSQL connection URL
        """
        return (
            f"postgresql://{self.admin_db_user}:{self.admin_db_password}"
            f"@{self.admin_db_host}:{self.admin_db_port}/{self.admin_db_name}"
        )

    @property
    def azure_authority_url(self) -> str:
        """
        Get Azure AD authority URL.

        Returns:
            Azure AD authority URL
        """
        if self.azure_authority:
            return self.azure_authority
        return f"https://login.microsoftonline.com/{self.azure_tenant_id}"

    @property
    def is_production(self) -> bool:
        """
        Check if running in production mode.

        Production mode requires:
        - Auth enabled
        - Azure AD enabled
        - Mock auth disabled
        - Non-default JWT secret

        Returns:
            True if running in production mode
        """
        return (
            self.enabled
            and self.azure_enabled
            and not self.mock_enabled
            and self.jwt_secret != "change-this-secret-in-production"
        )

    def validate_production_config(self) -> list[str]:
        """
        Validate configuration for production deployment.

        Returns:
            List of validation errors (empty if valid)
        """
        errors = []

        if not self.enabled:
            return errors  # Auth disabled, no validation needed

        if self.jwt_secret == "change-this-secret-in-production":
            errors.append("JWT_SECRET must be changed from default value in production")

        if self.azure_enabled:
            if not self.azure_tenant_id:
                errors.append("AZURE_TENANT_ID is required when Azure AD is enabled")
            if not self.azure_client_id:
                errors.append("AZURE_CLIENT_ID is required when Azure AD is enabled")
            if not self.azure_client_secret:
                errors.append("AZURE_CLIENT_SECRET is required when Azure AD is enabled")

        if not self.admin_db_password or self.admin_db_password == "postgres":
            errors.append("ADMIN_DB_PASSWORD must be set to a secure value in production")

        return errors

    def get_admin_async_pool(self):
        """
        Get PostgresPool instance for admin database async operations.

        Returns:
            PostgresPool instance for use with async/await
        """
        from ff_storage.db import PostgresPool

        return PostgresPool(
            dbname=self.admin_db_name,
            user=self.admin_db_user,
            password=self.admin_db_password,
            host=self.admin_db_host,
            port=self.admin_db_port,
            min_size=self.admin_db_pool_size,
            max_size=self.admin_db_pool_size + self.admin_db_max_overflow,
        )

    def get_admin_sync_db(self):
        """
        Get Postgres instance for admin database sync operations (schema sync).

        Returns:
            Postgres instance for synchronous database operations
        """
        from ff_storage.db import Postgres

        return Postgres(
            dbname=self.admin_db_name,
            user=self.admin_db_user,
            password=self.admin_db_password,
            host=self.admin_db_host,
            port=self.admin_db_port,
        )
