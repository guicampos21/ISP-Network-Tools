from __future__ import annotations

import os
from datetime import timedelta
from pathlib import Path


def read_secret(name: str) -> str:
    direct = os.getenv(name, "").strip()
    if direct:
        return direct
    path = os.getenv(f"{name}_FILE", "").strip()
    if path and Path(path).is_file():
        return Path(path).read_text(encoding="utf-8").strip()
    return ""


def database_url() -> str:
    user = os.getenv("DATABASE_USER", "isp_network_health")
    password = read_secret("DATABASE_PASSWORD")
    host = os.getenv("DATABASE_HOST", "postgres")
    port = os.getenv("DATABASE_PORT", "5432")
    name = os.getenv("DATABASE_NAME", "isp_network_health")
    return f"postgresql://{user}:{password}@{host}:{port}/{name}"


def app_config() -> dict[str, object]:
    environment = os.getenv("APP_ENV", "production").strip().lower()
    secure_prefix = "__Host-" if environment == "production" else ""
    return {
        "SECRET_KEY": read_secret("SECRET_KEY"),
        "SSO_SIGNING_SECRET": read_secret("SSO_SIGNING_SECRET"),
        "APP_ENV": environment,
        "SUITE_NAME": os.getenv("SUITE_NAME", "ISP Network Tools").strip()[:120],
        "ADMIN_BASE_URL": os.getenv("ADMIN_BASE_URL", "http://admin-center.localhost").rstrip("/"),
        "PUBLIC_BASE_URL": os.getenv("PUBLIC_BASE_URL", "http://geofeed.localhost").rstrip("/"),
        "HEALTH_BASE_URL": os.getenv("HEALTH_BASE_URL", "http://network-health.localhost").rstrip("/"),
        "REDIS_URL": os.getenv("REDIS_URL", "redis://redis:6379/1"),
        "TRUSTED_HOSTS": [
            item.strip()
            for item in os.getenv(
                "TRUSTED_HOSTS", "network-health.localhost,localhost,127.0.0.1"
            ).split(",")
            if item.strip()
        ],
        "SESSION_COOKIE_NAME": f"{secure_prefix}isp_network_health",
        "SESSION_COOKIE_SECURE": environment == "production",
        "SESSION_COOKIE_HTTPONLY": True,
        "SESSION_COOKIE_SAMESITE": "Lax",
        "SESSION_COOKIE_PATH": "/",
        "PERMANENT_SESSION_LIFETIME": timedelta(hours=8),
        "HEALTH_WORKER_MAX_WORKERS": max(1, min(int(os.getenv("HEALTH_WORKER_MAX_WORKERS", "32")), 96)),
    }
