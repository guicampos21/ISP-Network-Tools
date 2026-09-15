from __future__ import annotations

import functools
import hashlib
import json
import secrets
from datetime import datetime, timedelta, timezone
from typing import Callable

from flask import abort, current_app, g, has_request_context, request, session

from .models import AuditLog, SessionToken, User, db, utcnow


def normalize_email(value: str) -> str:
    return value.strip().casefold()


def current_user() -> User | None:
    if hasattr(g, "current_user"):
        return g.current_user
    user_id = session.get("user_id")
    user = db.session.get(User, user_id) if user_id else None
    if user and not user.active:
        session.clear()
        user = None
    g.current_user = user
    return user


def _token_digest(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _as_utc(value: datetime | None) -> datetime | None:
    """SQLite may return timezone-aware columns without their tzinfo."""
    if value is not None and value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value


def start_login(user: User, method: str, remember: bool = False) -> None:
    """Start an authenticated browser session and optionally issue a durable token."""
    session.clear()
    session["user_id"] = user.id
    session["auth_method"] = method
    session.permanent = True
    if remember:
        raw_token = secrets.token_urlsafe(32)
        db.session.add(
            SessionToken(
                token_digest=_token_digest(raw_token),
                user_id=user.id,
                expires_at=utcnow() + timedelta(days=current_app.config["REMEMBER_COOKIE_DAYS"]),
                user_agent=(request.user_agent.string or "")[:512],
            )
        )
        g.remember_cookie_value = raw_token


def revoke_remember_token() -> None:
    raw_token = request.cookies.get(current_app.config["REMEMBER_COOKIE_NAME"], "")
    if raw_token:
        token = SessionToken.query.filter_by(token_digest=_token_digest(raw_token)).first()
        if token and token.revoked_at is None:
            token.revoked_at = utcnow()
    g.expire_remember_cookie = True


def restore_remembered_session() -> None:
    if not has_request_context() or session.get("user_id"):
        return
    raw_token = request.cookies.get(current_app.config["REMEMBER_COOKIE_NAME"], "")
    if not raw_token:
        return
    token = SessionToken.query.filter_by(token_digest=_token_digest(raw_token)).first()
    now = utcnow()
    if not token or token.revoked_at or (_as_utc(token.expires_at) or now) <= now or not token.user or not token.user.active:
        g.expire_remember_cookie = True
        return
    session["user_id"] = token.user_id
    session["auth_method"] = token.user.auth_provider
    session.permanent = True
    token.last_used_at = now
    # Rotate the persistent credential when it is used. The old digest is
    # revoked before the replacement is issued, so a stolen token is single-use.
    replacement = secrets.token_urlsafe(32)
    token.revoked_at = now
    db.session.add(
        SessionToken(
            token_digest=_token_digest(replacement),
            user_id=token.user_id,
            expires_at=now + timedelta(days=current_app.config["REMEMBER_COOKIE_DAYS"]),
            user_agent=(request.user_agent.string or "")[:512],
        )
    )
    g.remember_cookie_value = replacement
    db.session.commit()


def login_required(view: Callable):
    @functools.wraps(view)
    def wrapped(*args, **kwargs):
        if not current_user():
            abort(401)
        return view(*args, **kwargs)

    return wrapped


def roles_required(*roles: str):
    def decorator(view: Callable):
        @functools.wraps(view)
        def wrapped(*args, **kwargs):
            user = current_user()
            if not user:
                abort(401)
            allowed = False
            for required in roles:
                if required == "super_admin":
                    allowed = allowed or user.is_super_admin()
                elif required == "admin":
                    allowed = allowed or user.is_admin()
                elif required == "editor":
                    allowed = allowed or user.can_edit()
                else:
                    allowed = allowed or user.role == required
            if not allowed:
                abort(403)
            return view(*args, **kwargs)

        return wrapped

    return decorator


def source_ip() -> str:
    if not has_request_context():
        return "internal"
    return (request.remote_addr or "")[:64]


def audit(
    action: str,
    entity_type: str = "",
    entity_id: object = "",
    details: dict | str | None = None,
    user: User | None = None,
) -> None:
    if isinstance(details, dict):
        safe_details = json.dumps(details, ensure_ascii=False, sort_keys=True)
    else:
        safe_details = str(details or "")
    db.session.add(
        AuditLog(
            user_id=(user or current_user()).id if (user or current_user()) else None,
            action=action[:80],
            entity_type=entity_type[:80],
            entity_id=str(entity_id)[:80],
            details=safe_details[:8000],
            source_ip=source_ip(),
        )
    )
