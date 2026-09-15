from __future__ import annotations

import base64
import hashlib

from cryptography.fernet import Fernet, InvalidToken
from flask import current_app

from .models import PortalSetting, User, db, utcnow


def _fernet() -> Fernet:
    key = base64.urlsafe_b64encode(hashlib.sha256(current_app.config["SECRET_KEY"].encode()).digest())
    return Fernet(key)


def _encrypt(value: str) -> str:
    return _fernet().encrypt(value.encode()).decode()


def _decrypt(value: str) -> str:
    try:
        return _fernet().decrypt(value.encode()).decode()
    except (InvalidToken, ValueError, UnicodeError):
        return ""


def get_setting(key: str, default: str = "") -> str:
    item = PortalSetting.query.filter_by(key=key).first()
    if not item:
        return default
    return _decrypt(item.value) if item.is_secret else item.value


def setting_info(key: str) -> dict:
    item = PortalSetting.query.filter_by(key=key).first()
    return {"configured": bool(item), "changed_at": item.updated_at if item else None}


def set_setting(key: str, value: str, *, secret: bool = False, user: User | None = None) -> None:
    item = PortalSetting.query.filter_by(key=key).first()
    if not item:
        item = PortalSetting(key=key, is_secret=secret)
        db.session.add(item)
    item.is_secret = secret
    item.value = _encrypt(value) if secret else value
    item.changed_by_id = user.id if user else None
    item.updated_at = utcnow()
