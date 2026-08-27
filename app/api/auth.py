"""API key authentication.

A key is presented either as `X-API-Key: <key>` or `Authorization: Bearer <key>`.
Both are accepted because integrators arrive with different habits and neither
is more secure than the other over TLS.

Keys are looked up by hash. A revoked key fails exactly like an unknown one:
the response never distinguishes "wrong key" from "key you no longer have",
because that difference is only useful to someone probing.
"""

from __future__ import annotations

import logging

from fastapi import Depends, Header, HTTPException, Request, status
from sqlalchemy.orm import Session

from ..store.models import ApiKey
from ..utils import utcnow
from .keys import hash_key

log = logging.getLogger("api")

_UNAUTHORIZED = HTTPException(
    status_code=status.HTTP_401_UNAUTHORIZED,
    detail="a valid API key is required",
    headers={"WWW-Authenticate": "Bearer"},
)


def get_session(request: Request) -> Session:
    """One session per request, committed by the route on success."""
    database = request.app.state.database
    session = database.session()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


def _presented(x_api_key: str | None, authorization: str | None) -> str:
    if x_api_key:
        return x_api_key.strip()
    if authorization and authorization.lower().startswith("bearer "):
        return authorization[7:].strip()
    return ""


def require_key(
    session: Session = Depends(get_session),
    x_api_key: str | None = Header(default=None, alias="X-API-Key"),
    authorization: str | None = Header(default=None),
) -> ApiKey:
    presented = _presented(x_api_key, authorization)
    if not presented:
        raise _UNAUTHORIZED

    record = (
        session.query(ApiKey).filter_by(key_hash=hash_key(presented)).one_or_none()
    )
    if record is None or record.revoked_at is not None:
        raise _UNAUTHORIZED

    record.last_used_at = utcnow()
    return record
