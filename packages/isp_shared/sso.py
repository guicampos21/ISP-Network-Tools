from __future__ import annotations

import base64
import hashlib
import hmac
import json
import secrets
import time
from typing import Any


class HandoffError(ValueError):
    """Raised when an inter-application handoff is not trustworthy."""


def _encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _decode(value: str) -> bytes:
    if not value or len(value) > 4096:
        raise HandoffError("token inválido")
    try:
        return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    except (ValueError, TypeError) as exc:
        raise HandoffError("token inválido") from exc


def issue_handoff(
    secret: str,
    *,
    subject: str,
    email: str,
    display_name: str,
    role: str,
    applications: list[str],
    audience: str,
    profile: str = "",
    next_path: str = "",
    ttl_seconds: int = 60,
) -> str:
    if not secret:
        raise HandoffError("SSO não configurado")
    now = int(time.time())
    payload = {
        "v": 1,
        "sub": str(subject)[:128],
        "email": str(email)[:254],
        "name": str(display_name)[:160],
        "role": str(role)[:64],
        # `role` remains for compatibility with older health containers. New
        # consumers should use the explicit profile claim.
        "profile": str(profile or role)[:64],
        "apps": sorted({str(item)[:64] for item in applications}),
        "aud": str(audience)[:64],
        "iat": now,
        "exp": now + max(15, min(int(ttl_seconds), 300)),
        "jti": secrets.token_urlsafe(18),
    }
    if next_path:
        payload["next"] = str(next_path)[:160]
    encoded = _encode(json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8"))
    signature = hmac.new(secret.encode("utf-8"), encoded.encode("ascii"), hashlib.sha256).digest()
    return f"{encoded}.{_encode(signature)}"


def verify_handoff(token: str, secret: str, *, audience: str) -> dict[str, Any]:
    if not secret:
        raise HandoffError("SSO não configurado")
    parts = str(token or "").split(".")
    if len(parts) != 2:
        raise HandoffError("token inválido")
    encoded, supplied_signature = parts
    expected_signature = _encode(
        hmac.new(secret.encode("utf-8"), encoded.encode("ascii"), hashlib.sha256).digest()
    )
    if not hmac.compare_digest(supplied_signature, expected_signature):
        raise HandoffError("token inválido")
    try:
        payload = json.loads(_decode(encoded).decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise HandoffError("token inválido") from exc
    if not isinstance(payload, dict) or payload.get("v") != 1:
        raise HandoffError("token inválido")
    if payload.get("aud") != audience or not payload.get("sub") or not payload.get("jti"):
        raise HandoffError("token inválido")
    now = int(time.time())
    try:
        issued_at = int(payload["iat"])
        expires_at = int(payload["exp"])
    except (KeyError, TypeError, ValueError) as exc:
        raise HandoffError("token inválido") from exc
    if issued_at > now + 30 or expires_at < now or expires_at <= issued_at:
        raise HandoffError("token expirado")
    apps = payload.get("apps")
    if not isinstance(apps, list) or any(not isinstance(item, str) for item in apps):
        raise HandoffError("token inválido")
    return payload
