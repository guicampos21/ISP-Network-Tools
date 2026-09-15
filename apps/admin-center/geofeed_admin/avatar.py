from __future__ import annotations

import os
import json
import io
import tempfile
import secrets
from pathlib import Path
from importlib.resources import files

import requests
from flask import current_app
from PIL import Image, UnidentifiedImageError

try:
    from dicebear import Avatar as DiceBearAvatar, Style as DiceBearStyle
except ImportError:  # pragma: no cover - development fallback before dependencies install
    DiceBearAvatar = None
    DiceBearStyle = None


AVATAR_PRESETS = {
    "friendly": "Amigável",
    "professional": "Profissional",
    "bearded": "Barbudo",
    "glasses": "Óculos",
    "turban": "Turbante",
    "creative": "Criativo",
}

DICEBEAR_STYLES = {
    "avataaars": {"label": "Avataaars", "license": "Uso pessoal e comercial", "attribution": "Avataaars por Pablo Stanley"},
    "adventurer": {"label": "Adventurer", "license": "CC BY 4.0", "attribution": "Adventurer por Lisa Wischofsky"},
    "lorelei": {"label": "Lorelei", "license": "CC0 1.0", "attribution": "Lorelei por DiceBear"},
    "notionists": {"label": "Notionists", "license": "CC0 1.0", "attribution": "Notionists por DiceBear"},
    "bottts": {"label": "Bottts", "license": "Uso pessoal e comercial", "attribution": "Bottts por Pablo Stanley"},
    "fun-emoji": {"label": "Fun Emoji", "license": "CC BY 4.0", "attribution": "Fun Emoji por Davis Uche"},
}

_DICEBEAR_DEFINITIONS = {}


def _dicebear_definition(style: str) -> dict:
    if style not in DICEBEAR_STYLES:
        style = "avataaars"
    if style not in _DICEBEAR_DEFINITIONS:
        raw = files("dicebear_styles").joinpath(f"{style}.json").read_text(encoding="utf-8")
        _DICEBEAR_DEFINITIONS[style] = json.loads(raw)
    return _DICEBEAR_DEFINITIONS[style]


def dicebear_catalog() -> dict:
    """Return only the style controls needed by the editor, not full definitions."""
    catalog = {}
    for style, metadata in DICEBEAR_STYLES.items():
        definition = _dicebear_definition(style)
        components = {}
        for name, component in definition.get("components", {}).items():
            variants = component.get("variants") if isinstance(component, dict) else None
            if variants:
                components[f"{name}Variant"] = list(variants)
        colors = {}
        for name, color in definition.get("colors", {}).items():
            values = color.get("values") if isinstance(color, dict) else None
            if values:
                colors[f"{name}Color"] = list(values)
        catalog[style] = {**metadata, "components": components, "colors": colors}
    return catalog


def sanitize_dicebear_config(value: str | dict | None, avatar_type: str = "custom") -> dict:
    """Normalize a stored DiceBear configuration against the selected style schema."""
    if isinstance(value, dict):
        raw = value
    else:
        try:
            raw = json.loads(value or "{}")
        except (TypeError, json.JSONDecodeError):
            raw = {}
    style = raw.get("style") if raw.get("style") in DICEBEAR_STYLES else "avataaars"
    catalog = dicebear_catalog()[style]
    allowed = {**catalog["components"], **catalog["colors"]}
    options = raw.get("options") if isinstance(raw.get("options"), dict) else {}
    clean_options = {}
    for key, choices in allowed.items():
        selected = options.get(key)
        if isinstance(selected, list):
            selected = selected[0] if selected else None
        if selected in choices:
            clean_options[key] = [selected]
    background = options.get("backgroundColor")
    if isinstance(background, str) and background.startswith("#"):
        background = background[1:]
    if isinstance(background, str) and len(background) in {3, 6} and all(char in "0123456789abcdefABCDEF" for char in background):
        clean_options["backgroundColor"] = [background]
    radius = options.get("borderRadius")
    if isinstance(radius, list):
        radius = radius[0] if radius else None
    try:
        radius = int(radius)
    except (TypeError, ValueError):
        radius = None
    if radius is not None and 0 <= radius <= 50:
        clean_options["borderRadius"] = radius
    seed = str(raw.get("seed") or "")[:80]
    if not seed or any(char not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-" for char in seed):
        seed = f"avatar-{secrets.token_hex(8)}"
    return {"type": "preset" if avatar_type == "preset" else "custom", "style": style, "seed": seed, "options": clean_options}


def dicebear_svg(value: str | dict | None, avatar_type: str = "custom") -> str:
    config = sanitize_dicebear_config(value, avatar_type)
    if DiceBearAvatar is None or DiceBearStyle is None:  # pragma: no cover
        return avatar_svg({})
    definition = _dicebear_definition(config["style"])
    options = {"seed": config["seed"], **config["options"]}
    return DiceBearAvatar(DiceBearStyle(definition), options).to_string()

AVATAR_PRESET_CONFIGS = {
    "friendly": {"gender": "feminine", "skin": "light", "face": "round", "hair": "long", "beard": "none", "moustache": "none", "nose": "small", "chin": "soft", "glasses": "none", "headwear": "none", "shirt": "blue"},
    "professional": {"gender": "masculine", "skin": "light", "face": "slim", "hair": "side", "beard": "none", "moustache": "none", "nose": "straight", "chin": "strong", "glasses": "none", "headwear": "none", "shirt": "suit"},
    "bearded": {"gender": "masculine", "skin": "tan", "face": "round", "hair": "curly", "beard": "full", "moustache": "none", "nose": "round", "chin": "strong", "glasses": "none", "headwear": "none", "shirt": "green"},
    "glasses": {"gender": "masculine", "skin": "brown", "face": "slim", "hair": "short", "beard": "none", "moustache": "none", "nose": "straight", "chin": "soft", "glasses": "round", "headwear": "none", "shirt": "purple"},
    "turban": {"gender": "masculine", "skin": "tan", "face": "round", "hair": "none", "beard": "short", "moustache": "none", "nose": "round", "chin": "strong", "glasses": "none", "headwear": "turban", "shirt": "orange"},
    "creative": {"gender": "feminine", "skin": "brown", "face": "round", "hair": "curly", "beard": "none", "moustache": "none", "nose": "small", "chin": "soft", "glasses": "none", "headwear": "none", "shirt": "red"},
}

_ALLOWED = {
    "gender": {"masculine": "Masculino", "feminine": "Feminino"},
    "skin": {"light": "#f2c6a8", "tan": "#c9825b", "brown": "#8d5038", "dark": "#5b352b"},
    "face": {"round": "rx=62 ry=72", "slim": "rx=52 ry=76"},
    "hair": {"none": "", "short": "<path d='M67 72c6-49 83-62 107-11-24-8-55-7-107 11z' fill='#33251f'/>", "side": "<path d='M61 71c12-49 83-54 111-13-35-15-64-4-111 13z' fill='#5a3828'/>", "curly": "<path d='M63 71c0-40 90-59 115-8l-12 13C143 48 99 48 63 71z' fill='#2b211e'/>", "long": "<path d='M57 119C43 53 73 26 111 28c40-2 70 28 53 91l-22-15c7-33-3-53-31-53-27 0-39 20-32 54z' fill='#4b2c29'/>", "bob": "<path d='M57 113c-8-58 18-85 54-85 38 0 65 31 52 87l-22-16c2-35-7-53-31-53-26 0-37 20-33 54z' fill='#171a2a'/>",},
    "beard": {"none": "", "short": "<path d='M74 145c12 37 70 38 91 0-12 55-76 55-91 0z' fill='#3e241d'/>", "full": "<path d='M67 132c3 75 92 83 113 0-14 22-31 30-57 28-24 1-41-7-56-28z' fill='#3e241d'/>",},
    "moustache": {"none": "", "thin": "<path d='M91 135q19-13 38 0-19 12-38 0z' fill='#3e241d'/>", "handlebar": "<path d='M110 135q-22-17-38 0 18 6 38 0 20 6 38 0-16-17-38 0z' fill='#3e241d'/>",},
    "nose": {"small": "M110 111v16l-7 4", "straight": "M110 108v22l-7 4", "round": "M110 109v18q0 9-9 8"},
    "chin": {"soft": "M101 151q9 5 18 0", "strong": "M98 151q12 10 24 0"},
    "glasses": {"none": "", "round": "<g fill='none' stroke='#271d2b' stroke-width='5'><circle cx='91' cy='111' r='19'/><circle cx='149' cy='111' r='19'/><path d='M110 111h20'/></g>", "square": "<g fill='none' stroke='#271d2b' stroke-width='5'><rect x='70' y='92' width='42' height='35' rx='7'/><rect x='128' y='92' width='42' height='35' rx='7'/><path d='M112 104h16'/></g>",},
    "headwear": {"none": "", "turban": "<path d='M59 83c7-52 104-60 123 0-34 12-88 12-123 0z' fill='#f3f1eb'/><path d='M57 84c31 12 91 12 127 0l-7 17c-37 12-83 12-113 0z' fill='#6e1e22'/>",},
    "shirt": {"blue": "#3c73b9", "green": "#3f8f65", "purple": "#7650af", "orange": "#c77637", "red": "#a94a4a", "suit": "#283246"},
}


def sanitize_avatar_config(value: str | dict | None) -> dict:
    if isinstance(value, dict):
        raw = value
    else:
        try:
            raw = json.loads(value or "{}")
        except (TypeError, json.JSONDecodeError):
            raw = {}
    result = {}
    for key, choices in _ALLOWED.items():
        selected = str(raw.get(key, ""))
        if selected in choices:
            result[key] = selected
        else:
            result[key] = next(iter(choices))
    return result


def avatar_svg(config: str | dict | None = None) -> str:
    selected = sanitize_avatar_config(config)
    skin = _ALLOWED["skin"][selected["skin"]]
    face = _ALLOWED["face"][selected["face"]]
    face_attrs = " ".join(face.split())
    shirt = _ALLOWED["shirt"][selected["shirt"]]
    beard = _ALLOWED["beard"][selected["beard"]]
    hair = _ALLOWED["hair"][selected["hair"]]
    glasses = _ALLOWED["glasses"][selected["glasses"]]
    headwear = _ALLOWED["headwear"][selected["headwear"]]
    moustache = _ALLOWED["moustache"][selected["moustache"]]
    nose = _ALLOWED["nose"][selected["nose"]]
    chin = _ALLOWED["chin"][selected["chin"]]
    shirt_extra = "<path d='M54 220v-28c0-26 31-44 66-44s66 18 66 44v28z' fill='#fff' opacity='.78'/>" if selected["shirt"] == "suit" else ""
    return f"""<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 220 240' role='img' aria-label='Avatar'><rect width='220' height='240' rx='28' fill='#f5f3f7'/><circle cx='110' cy='112' r='87' fill='#dfe5ee'/><path d='M38 240v-28c0-37 33-61 72-61s72 24 72 61v28z' fill='{shirt}'/>{shirt_extra}<ellipse cx='110' cy='113' {face_attrs} fill='{skin}'/>{hair}<path d='M84 110q10-8 20 0M126 110q10-8 20 0' fill='none' stroke='#2b1717' stroke-width='6' stroke-linecap='round'/><path d='{nose}' l11 6h-22' fill='none' stroke='#8d5038' stroke-width='4' stroke-linecap='round' stroke-linejoin='round'/><path d='{chin}' fill='none' stroke='#40181b' stroke-width='5' stroke-linecap='round'/>{beard}{moustache}{glasses}{headwear}</svg>"""


def _validated_image(content: bytes) -> tuple[str, str] | None:
    signatures = {
        "JPEG": (b"\xff\xd8\xff", ".jpg", "image/jpeg"),
        "PNG": (b"\x89PNG\r\n\x1a\n", ".png", "image/png"),
        "WEBP": (b"RIFF", ".webp", "image/webp"),
    }
    try:
        with Image.open(io.BytesIO(content)) as image:
            image.verify()
            detected = image.format
    except (UnidentifiedImageError, OSError, ValueError):
        return None
    match = signatures.get(detected or "")
    if not match or not content.startswith(match[0]):
        return None
    return match[1], match[2]


def store_uploaded_avatar(user, uploaded) -> None:
    """Store a small image using a server-generated filename and safe MIME allowlist."""
    if not uploaded or not uploaded.filename:
        return
    content = uploaded.read(2 * 1024 * 1024 + 1)
    match = _validated_image(content)
    if not match or len(content) > 2 * 1024 * 1024:
        raise ValueError("A foto deve ser JPG, PNG ou WEBP e ter no máximo 2 MB.")
    root = Path(current_app.config["AVATAR_ROOT"])
    root.mkdir(parents=True, exist_ok=True)
    for old in root.glob(f"{user.id}.*"):
        if old.is_file():
            old.unlink()
    target = root / f"{user.id}{match[0]}"
    temporary = target.with_suffix(target.suffix + ".tmp")
    temporary.write_bytes(content)
    os.chmod(temporary, 0o640)
    os.replace(temporary, target)
    user.avatar_path = target.name
    user.avatar_kind = "photo"


def clear_uploaded_avatar(user) -> None:
    """Remove the active uploaded photo without touching generated avatars."""
    filename = user.avatar_path or ""
    if filename and Path(filename).name == filename:
        path = Path(current_app.config["AVATAR_ROOT"]) / filename
        if path.is_file():
            path.unlink()
    user.avatar_path = ""
    user.avatar_kind = "initials"
    user.avatar_config = "{}"


def sync_user_avatar(user_id: int, access_token: str) -> None:
    """Cache the signed-in user's Microsoft 365 photo without storing its token."""
    if not current_app.config.get("GRAPH_PHOTO_ENABLED") or not access_token:
        return
    from .models import db, User
    user = db.session.get(User, user_id)
    # A manually selected avatar is an explicit user choice and should not be
    # replaced by the provider photo on every login.
    if user and (user.avatar_kind in AVATAR_PRESETS or user.avatar_kind in {"builder", "preset", "custom"}):
        return
    response = requests.get(
        "https://graph.microsoft.com/v1.0/me/photo/$value",
        headers={"Authorization": f"Bearer {access_token}"},
        timeout=5,
    )
    if response.status_code == 404:
        return
    response.raise_for_status()
    max_bytes = 2 * 1024 * 1024
    if not response.content or len(response.content) > max_bytes:
        return
    match = _validated_image(response.content)
    if not match:
        return
    root = Path(current_app.config["AVATAR_ROOT"])
    root.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=f"avatar-{user_id}-", suffix=".tmp", dir=root)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(response.content)
        os.chmod(temporary, 0o640)
        target = root / f"{user_id}{match[0]}"
        os.replace(temporary, target)
        user = db.session.get(User, user_id)
        if user:
            user.avatar_path = target.name
            user.avatar_kind = "photo"
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)
