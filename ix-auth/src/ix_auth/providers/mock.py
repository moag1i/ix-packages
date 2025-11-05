"""JWT Token Provider for InsurX authentication.

This module provides JWT token generation and validation for InsurX authentication.
It generates production-ready JWT tokens used in both:
1. Real OAuth flows (after Azure AD authentication)
2. Mock auth flows (for development/testing without Azure AD)

The tokens are signed with the application's JWT secret and contain InsurX-specific
claims (user_id, roles, permissions from InsurX database).
"""

import time
from typing import Any
from uuid import UUID, uuid4

import jwt

from ..config import AuthSettings
from ..models import Token, TokenPayload
from .base import BaseAuthProvider


class JWTTokenProvider(BaseAuthProvider):
    """
    JWT Token Provider for InsurX authentication.

    Generates and validates JWT tokens with InsurX-specific claims.
    Used in both OAuth flows (after Azure AD authentication) and mock auth flows.

    The generated tokens contain:
    - User ID (from InsurX database)
    - Roles (from InsurX RBAC system)
    - Permissions (from InsurX RBAC system)
    - Email, name, and other user attributes

    Example usage:
        settings = AuthSettings.with_prefix("IX_DS_AUTH_")
        provider = JWTTokenProvider(settings)

        # Generate token (typically after OAuth or mock auth)
        token = provider.generate_token(
            email="john.doe@example.com",
            name="John Doe",
            user_id=user.id,
            role="underwriter",
            permissions=["rules:read", "rules:write"]
        )

        # Validate token
        payload = await provider.validate_token(token.access_token)
    """

    def __init__(self, settings: AuthSettings):
        """
        Initialize mock auth provider.

        Args:
            settings: Authentication settings
        """
        super().__init__(settings)
        self.secret = settings.jwt_secret
        self.algorithm = settings.jwt_algorithm
        self.expire_minutes = settings.jwt_expire_minutes

    def generate_token(self, **kwargs: Any) -> Token:
        """
        Generate a mock JWT token.

        Args:
            **kwargs: Optional parameters:
                - email: User email (defaults to config value)
                - name: User name (defaults to config value)
                - user_id: User ID (defaults to config value or generates new UUID)
                - roles: List of user roles (required)
                - expires_in: Token lifetime in seconds (defaults to config value)
                - photo_url: Optional URL to user's profile photo (base64 data URI)
                - azure_oid: Optional Azure AD Object ID
                - azure_tenant_id: Optional Azure AD Tenant ID
                - tenant_id: InsurX tenant ID (None = admin with cross-tenant access)
                - tenant_type: Tenant type ('admin' | 'broker' | 'underwriter' | None)
                - accessible_tenant_ids: List of tenant IDs user can read from (cached)
                - permissions: Optional list of permissions (overrides role-based permissions)

        Returns:
            Token object with access_token and user info
        """
        # Extract kwargs with defaults
        email = kwargs.get("email", self.settings.mock_user_email)
        name = kwargs.get("name", self.settings.mock_user_name)

        # Roles must be provided as a list
        roles = kwargs.get("roles")
        if not roles:
            # Fall back to default from config if no roles provided
            roles = [self.settings.mock_default_role]

        expires_in = kwargs.get("expires_in", self.expire_minutes * 60)
        user_id = kwargs.get("user_id")
        photo_url = kwargs.get("photo_url")
        azure_oid = kwargs.get("azure_oid")
        azure_tenant_id = kwargs.get("azure_tenant_id")

        # Tenant context
        tenant_id = kwargs.get("tenant_id")  # InsurX tenant ID (None = admin)
        tenant_type = kwargs.get("tenant_type")  # 'admin' | 'broker' | 'underwriter' | None
        accessible_tenant_ids = kwargs.get(
            "accessible_tenant_ids", []
        )  # Cached readable tenant IDs

        # Parse or generate user_id
        if user_id is None:
            user_id = UUID(self.settings.mock_user_id)
        elif isinstance(user_id, str):
            try:
                user_id = UUID(user_id)
            except ValueError:
                user_id = uuid4()
        elif not isinstance(user_id, UUID):
            user_id = uuid4()

        # Get permissions for roles (allow override from kwargs)
        permissions = kwargs.get("permissions")
        if not permissions:
            # Combine permissions from all roles
            permissions = []
            for role in roles:
                permissions.extend(self._get_role_permissions(role))
            # Remove duplicates while preserving order
            permissions = list(dict.fromkeys(permissions))

        # Create token payload (include Azure OID/TID for photo cache lookup)
        now = int(time.time())
        payload = TokenPayload(
            sub=str(user_id),
            exp=now + expires_in,
            iat=now,
            iss="insurx-mock",
            user_id=user_id,
            email=email,
            name=name,
            roles=roles,  # Now properly passing all roles
            permissions=permissions,
            tenant_id=tenant_id,  # InsurX tenant ID
            tenant_type=tenant_type,  # InsurX tenant type
            accessible_tenant_ids=accessible_tenant_ids,  # Cached readable tenant IDs
            oid=azure_oid,  # Include Azure OID in JWT payload
            tid=azure_tenant_id,  # Include Azure Tenant ID in JWT payload
        )

        # Encode JWT (use mode="json" to properly serialize UUIDs)
        access_token = jwt.encode(
            payload.model_dump(mode="json"),
            self.secret,
            algorithm=self.algorithm,
        )

        # Build user dict with optional fields
        user_dict = {
            "id": str(user_id),
            "email": email,
            "name": name,
            "roles": roles,  # Now includes all roles
            "permissions": permissions,
        }

        # Add optional fields if provided
        if photo_url:
            user_dict["photo_url"] = photo_url
        if azure_oid:
            user_dict["azure_oid"] = azure_oid
        if azure_tenant_id:
            user_dict["azure_tenant_id"] = azure_tenant_id
        if tenant_id is not None:
            user_dict["tenant_id"] = str(tenant_id)
        if tenant_type is not None:
            user_dict["tenant_type"] = tenant_type
        if accessible_tenant_ids:
            user_dict["accessible_tenant_ids"] = [str(tid) for tid in accessible_tenant_ids]

        # Return token response
        return Token(
            access_token=access_token,
            token_type="bearer",
            expires_in=expires_in,
            user=user_dict,
        )

    async def validate_token(self, token: str) -> TokenPayload:
        """
        Validate and decode a JWT token.

        Args:
            token: JWT token string

        Returns:
            TokenPayload with decoded claims

        Raises:
            jwt.InvalidTokenError: If token is invalid or expired
        """
        try:
            payload_dict = jwt.decode(
                token,
                self.secret,
                algorithms=[self.algorithm],
            )
            return TokenPayload(**payload_dict)
        except jwt.ExpiredSignatureError as e:
            raise jwt.InvalidTokenError("Token has expired") from e
        except jwt.InvalidTokenError:
            raise

    def validate_token_sync(self, token: str) -> TokenPayload:
        """
        Synchronous version of validate_token for non-async contexts.

        Args:
            token: JWT token string

        Returns:
            TokenPayload with decoded claims

        Raises:
            jwt.InvalidTokenError: If token is invalid or expired
        """
        try:
            payload_dict = jwt.decode(
                token,
                self.secret,
                algorithms=[self.algorithm],
            )
            return TokenPayload(**payload_dict)
        except jwt.ExpiredSignatureError as e:
            raise jwt.InvalidTokenError("Token has expired") from e
        except jwt.InvalidTokenError:
            raise

    def _get_role_permissions(self, role: str) -> list[str]:
        """
        Get permissions for a given role.

        Args:
            role: Role name

        Returns:
            List of permission strings in format "resource:action"
        """
        # Permission mappings based on RBAC design
        role_permissions = {
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

        return role_permissions.get(role.lower(), [])
