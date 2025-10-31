"""Token models for JWT authentication.

These are DTO models (not stored in database) for handling
JWT tokens and OAuth flows.
"""

from uuid import UUID

from pydantic import BaseModel, Field


class TokenPayload(BaseModel):
    """
    JWT token payload.

    Standard JWT claims plus custom claims for user identity and roles.
    """

    # Standard JWT claims
    sub: str = Field(..., description="Subject (user ID or email)")
    exp: int = Field(..., description="Expiration timestamp")
    iat: int = Field(..., description="Issued at timestamp")
    iss: str = Field(..., description="Issuer (insurx or azure)")

    # Custom claims
    user_id: UUID | None = Field(None, description="User database ID")
    email: str = Field(..., description="User email")
    name: str = Field(..., description="User name")
    roles: list[str] = Field(default_factory=list, description="User roles")
    permissions: list[str] = Field(default_factory=list, description="User permissions")

    # Azure AD specific (optional)
    oid: str | None = Field(None, description="Azure AD Object ID")
    tid: str | None = Field(None, description="Azure AD Tenant ID")


class Token(BaseModel):
    """
    Token response model.

    Returned from authentication endpoints.
    """

    access_token: str = Field(..., description="JWT access token")
    token_type: str = Field("bearer", description="Token type (always 'bearer')")
    expires_in: int = Field(..., description="Token lifetime in seconds")
    refresh_token: str | None = Field(None, description="Refresh token (optional)")

    # User info included in response
    user: dict | None = Field(
        None,
        description="User information (id, email, name, roles)",
    )


class TokenRequest(BaseModel):
    """
    Token request model for OAuth code exchange.
    """

    code: str = Field(..., description="Authorization code from OAuth callback")
    state: str | None = Field(None, description="State parameter for CSRF protection")


class AzureTokenResponse(BaseModel):
    """
    Azure AD token response.

    Response from Azure AD token endpoint.
    """

    access_token: str
    token_type: str
    expires_in: int
    refresh_token: str | None = None
    id_token: str | None = None
    scope: str | None = None


class AzureUserInfo(BaseModel):
    """
    Azure AD user information from Microsoft Graph API.
    """

    id: str = Field(..., description="Azure AD Object ID (OID)")
    userPrincipalName: str = Field(..., description="User principal name (UPN)")
    mail: str | None = Field(None, description="User email")
    displayName: str = Field(..., description="User display name")
    givenName: str | None = Field(None, description="First name")
    surname: str | None = Field(None, description="Last name")
    has_photo: bool = Field(False, description="Whether user has a profile photo in Azure AD")


class MockTokenRequest(BaseModel):
    """
    Request model for generating mock tokens (development only).
    """

    email: str | None = Field(None, description="User email (default from config)")
    name: str | None = Field(None, description="User name (default from config)")
    role: str | None = Field(None, description="Role name (default from config)")
    expires_in: int = Field(3600, description="Token lifetime in seconds", ge=60, le=86400)
