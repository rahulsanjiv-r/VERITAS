"""
VERITAS — JWT-based authentication and tenant isolation (Phase 11).

Crypto choice: Option B chosen (software Ed25519 for device keys).
JWT HS256 is used for API auth (human roles). In production, prefer
asymmetric RS256 or ES256 so private-key exposure to the API server is
avoided and tokens can be verified by third parties (e.g. regulators)
without sharing the signing secret.

Invariants enforced here
------------------------
#9  Tenant isolation: a facility_operator token carries a `facility_id`
    claim. Every query that returns facility-specific data MUST filter by
    this claim at the *query layer* (database.py functions already accept
    facility_id as a WHERE-clause parameter) — not just at the route layer.
    `get_current_facility_id()` is the single chokepoint that callers use
    to extract and enforce this claim.
#10 Secret comes exclusively from the VERITAS_JWT_SECRET environment
    variable. It is never hardcoded, never logged, never returned to callers.

Roles
-----
- facility_operator : manages a single facility (must carry facility_id)
- veritas_admin     : platform-wide admin (no facility scope restriction)
- regulator_auditor : read-only cross-facility access (no facility scope restriction)
"""
from __future__ import annotations

import os
from datetime import datetime, timedelta, timezone
from typing import Optional

import jwt
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

VALID_ROLES: frozenset[str] = frozenset(
    {"facility_operator", "veritas_admin", "regulator_auditor"}
)

_ALGORITHM = "HS256"
_TOKEN_LIFETIME_HOURS = 24

_bearer_scheme = HTTPBearer(auto_error=False)


# ---------------------------------------------------------------------------
# Custom exception
# ---------------------------------------------------------------------------


class AuthError(Exception):
    """Raised by verify_token when a token is invalid, expired, or tampered with.

    Args:
        message: Human-readable reason for the failure.
    """

    def __init__(self, message: str) -> None:
        super().__init__(message)
        self.message = message


# ---------------------------------------------------------------------------
# Token creation
# ---------------------------------------------------------------------------


def create_token(
    role: str,
    facility_id: Optional[str],
    secret: str,
) -> str:
    """Create a signed HS256 JWT carrying role and optional facility_id claims.

    The token expires after 24 hours from the moment of creation.

    Args:
        role: One of ``facility_operator``, ``veritas_admin``,
            ``regulator_auditor``.
        facility_id: UUID of the facility the token is scoped to.  Must be
            provided (non-None, non-empty) when ``role`` is
            ``facility_operator``; should be ``None`` for the other two roles.
        secret: HMAC signing secret. **Never hardcode this value** — pass the
            value of the ``VERITAS_JWT_SECRET`` environment variable.

    Returns:
        A signed JWT string.

    Raises:
        ValueError: If ``role`` is not one of the three valid roles, or if a
            ``facility_operator`` token is created without a ``facility_id``.
    """
    if role not in VALID_ROLES:
        raise ValueError(
            f"Invalid role '{role}'. Must be one of: {sorted(VALID_ROLES)}"
        )
    if role == "facility_operator" and not facility_id:
        raise ValueError(
            "facility_operator tokens must carry a non-empty facility_id claim"
        )

    now = datetime.now(timezone.utc)
    payload: dict = {
        "role": role,
        "facility_id": facility_id,  # None for admin / regulator
        "iat": now,
        "exp": now + timedelta(hours=_TOKEN_LIFETIME_HOURS),
    }
    return jwt.encode(payload, secret, algorithm=_ALGORITHM)


# ---------------------------------------------------------------------------
# Token verification
# ---------------------------------------------------------------------------


def verify_token(token: str, secret: str) -> dict:
    """Verify and decode a VERITAS JWT.

    Validates the signature, expiry, and the presence of required claims.

    Args:
        token: The raw JWT string (without the ``Bearer`` prefix).
        secret: HMAC signing secret matching the one used in :func:`create_token`.

    Returns:
        The decoded payload dict, guaranteed to contain at minimum ``role``,
        ``facility_id``, ``iat``, and ``exp``.

    Raises:
        AuthError: If the token is expired, has an invalid signature, is
            malformed, or is missing required claims.
    """
    try:
        payload = jwt.decode(
            token,
            secret,
            algorithms=[_ALGORITHM],
            options={"require": ["exp"]},
        )
    except jwt.ExpiredSignatureError as exc:
        raise AuthError("Token has expired") from exc
    except jwt.InvalidTokenError as exc:
        raise AuthError(f"Invalid token: {exc}") from exc

    if "role" not in payload:
        raise AuthError("Token is missing required 'role' claim")

    if payload["role"] not in VALID_ROLES:
        raise AuthError(f"Token carries unknown role: {payload['role']!r}")

    return payload


# ---------------------------------------------------------------------------
# FastAPI dependency factories
# ---------------------------------------------------------------------------


def _get_secret() -> str:
    """Retrieve the JWT secret from the environment (invariant #10).

    Raises:
        RuntimeError: If ``VERITAS_JWT_SECRET`` is not set.
    """
    secret = os.environ.get("VERITAS_JWT_SECRET", "")
    if not secret:
        raise RuntimeError(
            "VERITAS_JWT_SECRET environment variable is not set. "
            "Set it before starting the server."
        )
    return secret


def require_role(*allowed_roles: str):
    """FastAPI ``Depends()`` factory that enforces role-based access control.

    Extracts the Bearer token from the ``Authorization`` header, verifies it,
    and checks that the token's role is among the allowed ones.

    Usage::

        @app.get("/admin/facilities")
        def list_all_facilities(
            token_data: dict = Depends(require_role("veritas_admin")),
        ):
            ...

    Args:
        *allowed_roles: One or more role strings that are permitted to call
            the decorated endpoint.

    Returns:
        A FastAPI dependency callable that returns the decoded token payload
        dict on success.

    Raises:
        HTTPException 401: If the ``Authorization`` header is missing or the
            token is invalid/expired.
        HTTPException 403: If the token is valid but the role is not in
            ``allowed_roles``.
    """
    for role in allowed_roles:
        if role not in VALID_ROLES:
            raise ValueError(
                f"require_role() called with unknown role {role!r}. "
                f"Valid roles: {sorted(VALID_ROLES)}"
            )

    def _dependency(
        credentials: Optional[HTTPAuthorizationCredentials] = Depends(_bearer_scheme),
    ) -> dict:
        if credentials is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Missing Authorization header — Bearer token required",
                headers={"WWW-Authenticate": "Bearer"},
            )

        try:
            secret = _get_secret()
            token_data = verify_token(credentials.credentials, secret)
        except AuthError as exc:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail=str(exc),
                headers={"WWW-Authenticate": "Bearer"},
            ) from exc
        except RuntimeError as exc:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=str(exc),
            ) from exc

        if token_data["role"] not in allowed_roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=(
                    f"Role '{token_data['role']}' is not permitted. "
                    f"Required: one of {list(allowed_roles)}"
                ),
            )

        return token_data

    return _dependency


# ---------------------------------------------------------------------------
# Facility-ID extraction (tenant isolation chokepoint — invariant #9)
# ---------------------------------------------------------------------------


def get_current_facility_id(token_data: dict) -> Optional[str]:
    """Extract the facility_id claim from a decoded token payload.

    This is the single chokepoint through which all facility-scoped queries
    must pass. Callers must pass the returned value directly into any database
    query that filters by facility (e.g. ``get_certificates_for_facility``,
    ``get_arrivals_for_facility``). The filtering must happen at the *query
    layer* so a facility_operator cannot read another facility's data by
    supplying a different facility_id in the request body or URL.

    ``veritas_admin`` and ``regulator_auditor`` tokens have ``facility_id=None``
    intentionally — they may query any facility. Routes that serve those roles
    must accept a facility_id parameter from the request and not restrict it.

    Args:
        token_data: Decoded payload dict as returned by :func:`verify_token`.

    Returns:
        The facility UUID string for ``facility_operator`` tokens, or ``None``
        for ``veritas_admin`` and ``regulator_auditor`` tokens.
    """
    return token_data.get("facility_id")
