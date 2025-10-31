"""JWT utility functions."""

from typing import Any

import jwt


def encode_jwt(
    payload: dict[str, Any],
    secret: str,
    algorithm: str = "HS256",
) -> str:
    """
    Encode a payload as a JWT token.

    Args:
        payload: Dictionary payload to encode
        secret: Secret key for signing
        algorithm: JWT algorithm (HS256, RS256, etc.)

    Returns:
        Encoded JWT token string
    """
    return jwt.encode(payload, secret, algorithm=algorithm)


def decode_jwt(
    token: str,
    secret: str,
    algorithm: str = "HS256",
    **kwargs: Any,
) -> dict[str, Any]:
    """
    Decode and validate a JWT token.

    Args:
        token: JWT token string
        secret: Secret key for validation
        algorithm: JWT algorithm to use
        **kwargs: Additional arguments for jwt.decode (audience, issuer, etc.)

    Returns:
        Decoded payload dictionary

    Raises:
        jwt.InvalidTokenError: If token is invalid
        jwt.ExpiredSignatureError: If token has expired
    """
    return jwt.decode(token, secret, algorithms=[algorithm], **kwargs)


def validate_jwt_signature(
    token: str,
    secret: str,
    algorithm: str = "HS256",
) -> bool:
    """
    Validate JWT signature without full validation.

    Args:
        token: JWT token string
        secret: Secret key for validation
        algorithm: JWT algorithm to use

    Returns:
        True if signature is valid, False otherwise
    """
    try:
        jwt.decode(
            token,
            secret,
            algorithms=[algorithm],
            options={"verify_signature": True, "verify_exp": False},
        )
        return True
    except jwt.InvalidTokenError:
        return False


def get_unverified_payload(token: str) -> dict[str, Any]:
    """
    Get JWT payload without verification.

    WARNING: This does not validate the token signature!
    Only use for debugging or when signature validation is done separately.

    Args:
        token: JWT token string

    Returns:
        Decoded payload dictionary (unverified)
    """
    return jwt.decode(token, options={"verify_signature": False})


def get_unverified_header(token: str) -> dict[str, Any]:
    """
    Get JWT header without verification.

    Useful for checking the algorithm before validation.

    Args:
        token: JWT token string

    Returns:
        JWT header dictionary
    """
    return jwt.get_unverified_header(token)
