"""Base authentication provider interface."""

from abc import ABC, abstractmethod
from typing import Any

from ..config import AuthSettings
from ..models import Token, TokenPayload


class BaseAuthProvider(ABC):
    """
    Base interface for authentication providers.

    All authentication providers (Azure AD, Mock, etc.) must implement this interface
    to ensure consistent behavior across different authentication methods.
    """

    def __init__(self, settings: AuthSettings):
        """
        Initialize the authentication provider.

        Args:
            settings: Authentication settings
        """
        self.settings = settings

    @abstractmethod
    async def validate_token(self, token: str) -> TokenPayload:
        """
        Validate a JWT token and return its payload.

        Args:
            token: JWT token string

        Returns:
            TokenPayload containing user information and claims

        Raises:
            ValueError: If token is invalid or expired
            Exception: For provider-specific errors
        """
        pass

    @abstractmethod
    def generate_token(self, **kwargs: Any) -> Token:
        """
        Generate an authentication token.

        Args:
            **kwargs: Provider-specific parameters for token generation

        Returns:
            Token object with access token and metadata

        Raises:
            ValueError: If required parameters are missing
            Exception: For provider-specific errors
        """
        pass

    def refresh_token(self, refresh_token: str) -> Token:
        """
        Refresh an access token using a refresh token.

        This is optional and not all providers need to implement it.

        Args:
            refresh_token: Refresh token string

        Returns:
            New Token object with refreshed access token

        Raises:
            NotImplementedError: If provider doesn't support refresh tokens
            ValueError: If refresh token is invalid
        """
        raise NotImplementedError(
            f"{self.__class__.__name__} does not support token refresh"
        )