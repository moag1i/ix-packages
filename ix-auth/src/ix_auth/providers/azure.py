"""Azure AD OAuth authentication provider.

Implements OAuth 2.0 authentication flow with Azure Active Directory:
1. Authorization Code Flow - For user-facing applications
2. Client Credentials Flow - For service-to-service authentication

Uses Microsoft Graph API for user profile retrieval.
"""

import time
from typing import Any
from urllib.parse import urlencode

import httpx
import jwt
from jwt import PyJWKClient

from ..config import AuthSettings
from ..models import AzureTokenResponse, AzureUserInfo, Token, TokenPayload
from .base import BaseAuthProvider


class AzureADProvider(BaseAuthProvider):
    """
    Azure Active Directory OAuth provider.

    Handles OAuth flows and token validation using Azure AD and Microsoft Graph API.

    Example usage:
        settings = AuthSettings.with_prefix("IX_DS_AUTH_")
        provider = AzureADProvider(settings)

        # Get authorization URL
        auth_url, state = provider.get_authorization_url()
        # Redirect user to auth_url

        # Exchange code for token (after callback)
        token = await provider.exchange_code_for_token(code)

        # Validate token
        payload = await provider.validate_token(token.access_token)

        # Get user info
        user_info = await provider.get_user_info(access_token)
    """

    def __init__(self, settings: AuthSettings):
        """
        Initialize Azure AD provider.

        Args:
            settings: Authentication settings
        """
        super().__init__(settings)
        self.tenant_id = settings.azure_tenant_id
        self.client_id = settings.azure_client_id
        self.client_secret = settings.azure_client_secret
        self.redirect_uri = settings.azure_redirect_uri
        self.scopes = settings.azure_scopes
        self.authority = settings.azure_authority_url

        # Azure AD endpoints
        self.authorization_endpoint = f"{self.authority}/oauth2/v2.0/authorize"
        self.token_endpoint = f"{self.authority}/oauth2/v2.0/token"
        self.jwks_uri = f"{self.authority}/discovery/v2.0/keys"

        # Microsoft Graph API
        self.graph_api_base = "https://graph.microsoft.com/v1.0"

        # JWKS client for token validation (lazy loaded)
        self._jwks_client: PyJWKClient | None = None

    @property
    def jwks_client(self) -> PyJWKClient:
        """Get or create JWKS client for token validation."""
        if self._jwks_client is None:
            self._jwks_client = PyJWKClient(self.jwks_uri)
        return self._jwks_client

    def generate_token(self, **kwargs: Any) -> Token:
        """
        Generate token is not supported for Azure AD provider.

        Azure AD tokens must be obtained through OAuth flows.

        Raises:
            NotImplementedError: Always, as Azure doesn't support direct token generation
        """
        raise NotImplementedError(
            "Azure AD provider does not support direct token generation. "
            "Use exchange_code_for_token() or get_client_credentials_token() instead."
        )

    def get_authorization_url(self, state: str | None = None) -> tuple[str, str]:
        """
        Get OAuth authorization URL for user login.

        Args:
            state: Optional state parameter for CSRF protection (generated if not provided)

        Returns:
            Tuple of (authorization_url, state)
        """
        import secrets

        # Generate state if not provided
        if state is None:
            state = secrets.token_urlsafe(32)

        params = {
            "client_id": self.client_id,
            "response_type": "code",
            "redirect_uri": self.redirect_uri,
            "response_mode": "query",
            "scope": " ".join(self.scopes),
            "state": state,
        }

        auth_url = f"{self.authorization_endpoint}?{urlencode(params)}"
        return auth_url, state

    async def exchange_code_for_token(
        self,
        code: str,
        include_user_info: bool = True,
    ) -> Token:
        """
        Exchange authorization code for access token.

        Args:
            code: Authorization code from OAuth callback
            include_user_info: Whether to fetch user info from Graph API

        Returns:
            Token object with access_token and optional user info

        Raises:
            httpx.HTTPError: If token exchange fails
        """
        data = {
            "client_id": self.client_id,
            "client_secret": self.client_secret,
            "code": code,
            "redirect_uri": self.redirect_uri,
            "grant_type": "authorization_code",
            "scope": " ".join(self.scopes),
        }

        async with httpx.AsyncClient() as client:
            response = await client.post(
                self.token_endpoint,
                data=data,
                headers={"Content-Type": "application/x-www-form-urlencoded"},
            )
            response.raise_for_status()
            azure_token = AzureTokenResponse(**response.json())

        # Optionally fetch user info
        user_info_dict = None
        if include_user_info:
            user_info = await self.get_user_info(azure_token.access_token)
            user_info_dict = {
                "id": user_info.id,
                "email": user_info.mail or user_info.userPrincipalName,
                "name": user_info.displayName,
            }

        return Token(
            access_token=azure_token.access_token,
            token_type=azure_token.token_type,
            expires_in=azure_token.expires_in,
            refresh_token=azure_token.refresh_token,
            user=user_info_dict,
        )

    async def get_client_credentials_token(self) -> Token:
        """
        Get token using client credentials flow (service-to-service).

        Returns:
            Token object with access_token

        Raises:
            httpx.HTTPError: If token request fails
        """
        data = {
            "client_id": self.client_id,
            "client_secret": self.client_secret,
            "scope": "https://graph.microsoft.com/.default",
            "grant_type": "client_credentials",
        }

        async with httpx.AsyncClient() as client:
            response = await client.post(
                self.token_endpoint,
                data=data,
                headers={"Content-Type": "application/x-www-form-urlencoded"},
            )
            response.raise_for_status()
            azure_token = AzureTokenResponse(**response.json())

        return Token(
            access_token=azure_token.access_token,
            token_type=azure_token.token_type,
            expires_in=azure_token.expires_in,
        )

    async def get_user_info(self, access_token: str) -> AzureUserInfo:
        """
        Get user information from Microsoft Graph API.

        Args:
            access_token: Azure AD access token

        Returns:
            AzureUserInfo with user profile data

        Raises:
            httpx.HTTPError: If API request fails
        """
        async with httpx.AsyncClient() as client:
            response = await client.get(
                f"{self.graph_api_base}/me",
                headers={"Authorization": f"Bearer {access_token}"},
            )
            response.raise_for_status()
            return AzureUserInfo(**response.json())

    async def get_user_photo(self, access_token: str, size: str = "96x96") -> bytes | None:
        """
        Get user profile photo from Microsoft Graph API.

        Args:
            access_token: Azure AD access token
            size: Photo size (48x48, 64x64, 96x96, 120x120, 240x240, 360x360, 432x432, 504x504, 648x648)

        Returns:
            Photo bytes (JPEG/PNG) or None if user has no photo

        Raises:
            httpx.HTTPError: If API request fails (except 404)
        """
        async with httpx.AsyncClient() as client:
            response = await client.get(
                f"{self.graph_api_base}/me/photos/{size}/$value",
                headers={"Authorization": f"Bearer {access_token}"},
            )

            # User has no profile photo
            if response.status_code == 404:
                return None

            response.raise_for_status()
            return response.content

    async def validate_token(self, token: str) -> TokenPayload:
        """
        Validate Azure AD JWT token using JWKS.

        Args:
            token: JWT token string

        Returns:
            TokenPayload with decoded claims

        Raises:
            jwt.InvalidTokenError: If token is invalid or expired
        """
        try:
            # Get signing key from JWKS
            signing_key = self.jwks_client.get_signing_key_from_jwt(token)

            # Decode and validate token
            payload_dict = jwt.decode(
                token,
                signing_key.key,
                algorithms=["RS256"],
                audience=self.client_id,
                issuer=f"https://login.microsoftonline.com/{self.tenant_id}/v2.0",
            )

            # Convert to TokenPayload
            return self._azure_payload_to_token_payload(payload_dict)

        except jwt.ExpiredSignatureError as e:
            raise jwt.InvalidTokenError("Token has expired") from e
        except jwt.InvalidTokenError:
            raise

    def _azure_payload_to_token_payload(self, azure_payload: dict[str, Any]) -> TokenPayload:
        """
        Convert Azure AD token payload to our TokenPayload format.

        Args:
            azure_payload: Raw JWT payload from Azure AD

        Returns:
            TokenPayload with standardized claims
        """
        # Extract standard claims
        user_id = azure_payload.get("oid")  # Azure Object ID
        email = azure_payload.get("preferred_username") or azure_payload.get("email")
        name = azure_payload.get("name", "")

        # Create TokenPayload
        # Note: Roles and permissions will be populated by user service
        # after fetching from our database
        return TokenPayload(
            sub=user_id or email,
            exp=azure_payload.get("exp", int(time.time()) + 3600),
            iat=azure_payload.get("iat", int(time.time())),
            iss="azure",
            user_id=None,  # Will be set after user lookup
            email=email,
            name=name,
            roles=[],  # Will be populated after database lookup
            permissions=[],  # Will be populated after database lookup
            oid=user_id,
            tid=azure_payload.get("tid"),  # Azure Tenant ID
        )

    async def refresh_token_async(self, refresh_token: str) -> Token:
        """
        Refresh access token using refresh token.

        Args:
            refresh_token: Refresh token from previous authentication

        Returns:
            New Token object with fresh access_token

        Raises:
            httpx.HTTPError: If token refresh fails
        """
        data = {
            "client_id": self.client_id,
            "client_secret": self.client_secret,
            "refresh_token": refresh_token,
            "grant_type": "refresh_token",
            "scope": " ".join(self.scopes),
        }

        async with httpx.AsyncClient() as client:
            response = await client.post(
                self.token_endpoint,
                data=data,
                headers={"Content-Type": "application/x-www-form-urlencoded"},
            )
            response.raise_for_status()
            azure_token = AzureTokenResponse(**response.json())

        return Token(
            access_token=azure_token.access_token,
            token_type=azure_token.token_type,
            expires_in=azure_token.expires_in,
            refresh_token=azure_token.refresh_token,
        )

    def refresh_token(self, refresh_token: str) -> Token:
        """
        Synchronous wrapper for refresh_token_async.

        This is provided to satisfy the base class interface.

        Args:
            refresh_token: Refresh token from previous authentication

        Returns:
            New Token object with fresh access_token

        Raises:
            RuntimeError: As this requires async context
        """
        import asyncio

        loop = asyncio.get_event_loop()
        return loop.run_until_complete(self.refresh_token_async(refresh_token))
