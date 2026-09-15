from __future__ import annotations

import json
import secrets
from datetime import datetime

import pyotp
import qrcode
from cryptography.fernet import Fernet, InvalidToken
from flask import current_app
from werkzeug.security import check_password_hash, generate_password_hash

from .models import User, utcnow


def _fernet() -> Fernet:
    import base64
    import hashlib

    key = base64.urlsafe_b64encode(
        hashlib.sha256(current_app.config["SECRET_KEY"].encode("utf-8")).digest()
    )
    return Fernet(key)


def _encrypt(value: str) -> str:
    return _fernet().encrypt(value.encode("utf-8")).decode("ascii")


def _decrypt(value: str) -> str:
    try:
        return _fernet().decrypt(value.encode("ascii")).decode("utf-8")
    except (InvalidToken, ValueError, UnicodeError):
        return ""


def secret_for(user: User) -> str:
    return _decrypt(user.totp_secret or "")


def grace_active(user: User, now: datetime | None = None) -> bool:
    return bool(user.totp_grace_until and user.totp_grace_until > (now or utcnow()))


def setup_required(user: User) -> bool:
    return user.auth_provider == "local" and not user.totp_enabled and not grace_active(user)


def challenge_required(user: User) -> bool:
    return user.auth_provider == "local" and user.totp_enabled and bool(secret_for(user)) and not grace_active(user)


def setup_payload(user: User) -> tuple[str, str, list[str]]:
    secret = secret_for(user)
    if not secret:
        secret = pyotp.random_base32()
        user.totp_secret = _encrypt(secret)
    recovery_codes = [secrets.token_hex(5) for _ in range(8)]
    uri = pyotp.TOTP(secret).provisioning_uri(
        name=user.username or user.email,
        issuer_name=current_app.config.get("TOTP_ISSUER", "ISP Network Tools"),
    )
    return secret, uri, recovery_codes


def store_pending_recovery_codes(user: User, codes: list[str]) -> None:
    user.recovery_codes = "pending:" + _encrypt(json.dumps(codes, separators=(",", ":")))


def pending_recovery_codes(user: User) -> list[str]:
    if not (user.recovery_codes or "").startswith("pending:"):
        return []
    raw = _decrypt(user.recovery_codes.removeprefix("pending:"))
    try:
        values = json.loads(raw)
    except json.JSONDecodeError:
        return []
    return [str(value) for value in values if isinstance(value, str)]


def qr_matrix(uri: str) -> list[list[bool]]:
    qr = qrcode.QRCode(version=None, error_correction=qrcode.constants.ERROR_CORRECT_M, box_size=1, border=2)
    qr.add_data(uri)
    qr.make(fit=True)
    return qr.get_matrix()


def enable_totp(user: User, recovery_codes: list[str]) -> None:
    user.totp_enabled = True
    user.recovery_codes = json.dumps(
        [generate_password_hash(code) for code in recovery_codes],
        separators=(",", ":"),
    )


def verify_code(user: User, code: str) -> bool:
    secret = secret_for(user)
    # A two-step window tolerates clock skew during setup while keeping the
    # one-time code short-lived (the server and device may differ by a minute).
    return bool(secret and pyotp.TOTP(secret).verify(code.strip(), valid_window=2))


def consume_recovery_code(user: User, code: str) -> bool:
    try:
        stored = json.loads(user.recovery_codes or "[]")
    except json.JSONDecodeError:
        stored = []
    for index, digest in enumerate(stored):
        if check_password_hash(digest, code.strip().lower()):
            stored.pop(index)
            user.recovery_codes = json.dumps(stored, separators=(",", ":"))
            return True
    return False
