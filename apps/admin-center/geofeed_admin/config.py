import os
from datetime import timedelta
from pathlib import Path
from urllib.parse import quote_plus


def _bool(name: str, default: bool = False) -> bool:
    return os.getenv(name, str(default)).strip().lower() in {"1", "true", "yes", "on"}


def _read_secret(name: str) -> str:
    direct = os.getenv(name, "").strip()
    if direct:
        return direct
    secret_file = os.getenv(f"{name}_FILE", "").strip()
    if secret_file and Path(secret_file).is_file():
        return Path(secret_file).read_text(encoding="utf-8").strip()
    return ""


class Config:
    APP_ENV = os.getenv("APP_ENV", "production").strip().lower()
    SECRET_KEY = _read_secret("SECRET_KEY")
    SUITE_NAME = os.getenv("SUITE_NAME", "ISP Network Tools").strip()[:120]
    COMPANY_NAME = os.getenv("COMPANY_NAME", "Sua empresa").strip()[:120]
    PUBLIC_CONTACT_EMAIL = os.getenv("PUBLIC_CONTACT_EMAIL", "").strip()[:254]
    ADMIN_BASE_URL = os.getenv("ADMIN_BASE_URL", "http://admin-center.localhost").rstrip("/")
    PUBLIC_BASE_URL = os.getenv("PUBLIC_BASE_URL", "http://geofeed.localhost").rstrip("/")
    HEALTH_BASE_URL = os.getenv("HEALTH_BASE_URL", "http://network-health.localhost").rstrip("/")
    DATABASE_HOST = os.getenv("DATABASE_HOST", "").strip()
    DATABASE_PORT = os.getenv("DATABASE_PORT", "5432").strip()
    DATABASE_NAME = os.getenv("DATABASE_NAME", "isp_core").strip()
    DATABASE_USER = os.getenv("DATABASE_USER", "isp_core").strip()
    DATABASE_PASSWORD = _read_secret("DATABASE_PASSWORD")
    DATABASE_PATH = os.getenv("DATABASE_PATH", "/data/geofeed-admin.sqlite3")
    SQLALCHEMY_DATABASE_URI = (
        os.getenv("DATABASE_URL", "").strip()
        or (
            f"postgresql+psycopg://{quote_plus(DATABASE_USER)}:{quote_plus(DATABASE_PASSWORD)}"
            f"@{DATABASE_HOST}:{DATABASE_PORT}/{quote_plus(DATABASE_NAME)}"
            if DATABASE_HOST
            else f"sqlite:///{DATABASE_PATH}"
        )
    )
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SQLALCHEMY_ENGINE_OPTIONS = (
        {"pool_pre_ping": True, "pool_recycle": 1800}
        if DATABASE_HOST
        else {"connect_args": {"timeout": 30, "check_same_thread": False}}
    )
    PUBLIC_ROOT = os.getenv("PUBLIC_ROOT", "/publish")
    BACKUP_ROOT = os.getenv("BACKUP_ROOT", "/backups")
    TRUSTED_HOSTS = [
        item.strip()
        for item in os.getenv(
            "TRUSTED_HOSTS", "admin-center.localhost"
        ).split(",")
        if item.strip()
    ]
    SESSION_COOKIE_SECURE = APP_ENV == "production"
    SESSION_COOKIE_NAME = "__Host-isp_network_tools"
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"
    SESSION_COOKIE_PATH = "/"
    PREFERRED_URL_SCHEME = "https"
    REMEMBER_COOKIE_NAME = "__Host-geofeed_remember"
    REMEMBER_COOKIE_DAYS = max(1, int(os.getenv("REMEMBER_COOKIE_DAYS", "30")))
    TOTP_ISSUER = os.getenv("TOTP_ISSUER", SUITE_NAME).strip()
    PERMANENT_SESSION_LIFETIME = timedelta(
        hours=int(os.getenv("SESSION_HOURS", "8"))
    )
    MAX_CONTENT_LENGTH = 5 * 1024 * 1024
    WTF_CSRF_TIME_LIMIT = int(os.getenv("CSRF_HOURS", "8")) * 60 * 60
    RATELIMIT_STORAGE_URI = os.getenv("RATELIMIT_STORAGE_URI", os.getenv("REDIS_URL", "memory://"))
    RATELIMIT_HEADERS_ENABLED = True

    ENTRA_TENANT_ID = os.getenv("ENTRA_TENANT_ID", "").strip()
    ENTRA_CLIENT_ID = os.getenv("ENTRA_CLIENT_ID", "").strip()
    ENTRA_CLIENT_SECRET = _read_secret("ENTRA_CLIENT_SECRET")
    ENTRA_INITIAL_ADMIN_EMAIL = os.getenv(
        "ENTRA_INITIAL_ADMIN_EMAIL", ""
    ).strip().lower()
    GOOGLE_CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID", "").strip()
    GOOGLE_CLIENT_SECRET = _read_secret("GOOGLE_CLIENT_SECRET")
    DEV_AUTH = _bool("DEV_AUTH") and APP_ENV == "development"
    GRAPH_PHOTO_ENABLED = _bool("GRAPH_PHOTO_ENABLED")
    AVATAR_ROOT = os.getenv("AVATAR_ROOT", "/data/avatars")
    BRANDING_ROOT = os.getenv("BRANDING_ROOT", "/data/branding")
    LOCAL_AUTH_ENABLED = _bool("LOCAL_AUTH_ENABLED", True)

    HEALTHCHECK_INTERVAL_MINUTES = max(
        5, int(os.getenv("HEALTHCHECK_INTERVAL_MINUTES", "60"))
    )
    # When set, health checks stay inside the Docker network and avoid
    # NAT/hairpin limitations while still validating the public Nginx server.
    HEALTHCHECK_INTERNAL_BASE_URL = os.getenv(
        "HEALTHCHECK_INTERNAL_BASE_URL", ""
    ).rstrip("/")
    SMTP_HOST = os.getenv("SMTP_HOST", "").strip()
    SMTP_PORT = int(os.getenv("SMTP_PORT", "587"))
    SMTP_STARTTLS = _bool("SMTP_STARTTLS", True)
    SMTP_USERNAME = os.getenv("SMTP_USERNAME", "").strip()
    SMTP_PASSWORD = _read_secret("SMTP_PASSWORD")
    SMTP_FROM = os.getenv(
        "SMTP_FROM", ""
    )
    SSO_SIGNING_SECRET = _read_secret("SSO_SIGNING_SECRET")
    SETUP_TOKEN = _read_secret("SETUP_TOKEN")

    @classmethod
    def validate(cls) -> None:
        if not cls.SECRET_KEY:
            raise RuntimeError("SECRET_KEY não configurada")
        if cls.APP_ENV == "production" and cls.DEV_AUTH:
            raise RuntimeError("DEV_AUTH não pode ser habilitado em produção")
        if cls.APP_ENV == "production" and not cls.SSO_SIGNING_SECRET:
            raise RuntimeError("SSO_SIGNING_SECRET não configurada")
