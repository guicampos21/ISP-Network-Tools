from __future__ import annotations

import os
import json
import re
import base64
from pathlib import Path

from authlib.integrations.flask_client import OAuth
from flask import Flask, g, jsonify, redirect, render_template, request, url_for
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_wtf.csrf import CSRFProtect
from sqlalchemy import event, inspect, text
from sqlalchemy.engine import Engine
from sqlalchemy.exc import IntegrityError, OperationalError
from werkzeug.middleware.proxy_fix import ProxyFix

from .config import Config
from .models import Application, InAppNotification, JobFunction, Role, Sector, User, db
from .avatar import AVATAR_PRESET_CONFIGS, AVATAR_PRESETS, avatar_svg, dicebear_catalog
from .security import current_user, restore_remembered_session


csrf = CSRFProtect()
oauth = OAuth()
limiter = Limiter(key_func=get_remote_address, default_limits=["300 per hour"])


@event.listens_for(Engine, "connect")
def configure_sqlite(connection, _record):
    if connection.__class__.__module__.startswith("sqlite3"):
        cursor = connection.cursor()
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.execute("PRAGMA journal_mode=WAL")
        cursor.execute("PRAGMA busy_timeout=30000")
        cursor.close()


def create_app(test_config: dict | None = None) -> Flask:
    app = Flask(__name__)
    app.config.from_object(Config)
    if test_config:
        app.config.update(test_config)
    if not test_config or "SESSION_COOKIE_NAME" not in test_config:
        secure_prefix = "__Host-" if app.config.get("APP_ENV") == "production" else ""
        app.config["SESSION_COOKIE_NAME"] = f"{secure_prefix}isp_network_tools"
    if not test_config or "REMEMBER_COOKIE_NAME" not in test_config:
        secure_prefix = "__Host-" if app.config.get("APP_ENV") == "production" else ""
        app.config["REMEMBER_COOKIE_NAME"] = f"{secure_prefix}geofeed_remember"
    if not app.config.get("SECRET_KEY"):
        raise RuntimeError("SECRET_KEY não configurada")
    if app.config.get("APP_ENV") == "production" and not app.config.get("SSO_SIGNING_SECRET"):
        raise RuntimeError("SSO_SIGNING_SECRET não configurada")

    Path(app.config["DATABASE_PATH"]).parent.mkdir(parents=True, exist_ok=True)
    Path(app.config["PUBLIC_ROOT"]).mkdir(parents=True, exist_ok=True)
    Path(app.config["BACKUP_ROOT"]).mkdir(parents=True, exist_ok=True)
    Path(app.config["BRANDING_ROOT"]).mkdir(parents=True, exist_ok=True)

    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)
    db.init_app(app)
    csrf.init_app(app)
    limiter.init_app(app)
    oauth.init_app(app)

    # The project intentionally keeps SQLite migrations small and explicit.
    # This additive migration lets an existing installation accept local users
    # before the first request after a deploy, without logging any secrets.
    with app.app_context():
        try:
            if str(app.config.get("SQLALCHEMY_DATABASE_URI", "")).startswith("postgresql"):
                with db.engine.begin() as connection:
                    connection.execute(
                        text("SELECT pg_advisory_xact_lock(hashtext('isp-network-tools-admin-schema'))")
                    )
                    db.metadata.create_all(bind=connection)
            else:
                db.create_all()
        except OperationalError as exc:
            # Gunicorn and the worker can boot concurrently against SQLite;
            # another process may win the check-then-create race for a table.
            if "already exists" not in str(exc).lower():
                raise
            db.session.rollback()
        try:
            for name in ("Engenharia de redes", "Analista de infraestrutura", "Técnico de redes", "Administrador de sistemas"):
                if not JobFunction.query.filter_by(name=name).first():
                    db.session.add(JobFunction(name=name))
            db.session.commit()
        except IntegrityError:
            db.session.rollback()
        columns = {column["name"] for column in inspect(db.engine).get_columns("users")}
        additions = {
            "password_hash": "VARCHAR(255)",
            "username": "VARCHAR(80)",
            "first_name": "VARCHAR(80) NOT NULL DEFAULT ''",
            "last_name": "VARCHAR(80) NOT NULL DEFAULT ''",
            "nickname": "VARCHAR(80) NOT NULL DEFAULT ''",
            "department": "VARCHAR(120) NOT NULL DEFAULT ''",
            "job_title": "VARCHAR(120) NOT NULL DEFAULT ''",
            "auth_provider": "VARCHAR(16) NOT NULL DEFAULT 'm365'",
            "password_change_required": "BOOLEAN NOT NULL DEFAULT 0",
            "totp_secret": "VARCHAR(64)",
            "totp_enabled": "BOOLEAN NOT NULL DEFAULT 0",
            "totp_grace_until": "DATETIME",
            "recovery_codes": "TEXT NOT NULL DEFAULT ''",
            "avatar_kind": "VARCHAR(32) NOT NULL DEFAULT 'initials'",
            "avatar_path": "VARCHAR(255) NOT NULL DEFAULT ''",
            "google_sub": "VARCHAR(128)",
            "avatar_config": "TEXT NOT NULL DEFAULT '{}'",
            "deleted_at": "DATETIME",
            "deleted_by_id": "INTEGER REFERENCES users(id)",
        }
        for name, definition in additions.items():
            if name in columns:
                continue
            try:
                with db.engine.begin() as connection:
                    connection.execute(text(f"ALTER TABLE users ADD COLUMN {name} {definition}"))
            except OperationalError as exc:
                # A second admin/worker process may have completed the same
                # additive migration concurrently.
                if "duplicate column name" not in str(exc).lower():
                    raise
        with db.engine.begin() as connection:
            connection.execute(
                text("CREATE UNIQUE INDEX IF NOT EXISTS ix_users_username_unique "
                     "ON users(username) WHERE username IS NOT NULL")
            )
            connection.execute(
                text("CREATE INDEX IF NOT EXISTS ix_users_deleted_at ON users(deleted_at)")
            )
        # Usernames are reserved for local authentication. External identities
        # are identified by their provider e-mail and must not get a local login.
        for user in User.query.filter(User.auth_provider.in_(["m365", "google"]), User.username.isnot(None)).all():
            user.username = None
        for user in User.query.filter(User.auth_provider == "local", User.username.is_(None)).all():
            base = re.sub(r"[^a-z0-9._-]+", "-", user.email.split("@", 1)[0].casefold()).strip(".-_") or f"user-{user.id}"
            username = base[:80]
            suffix = 1
            while User.query.filter(User.username == username).first():
                suffix += 1
                suffix_text = f"-{suffix}"
                username = f"{base[:80-len(suffix_text)]}{suffix_text}"
            user.username = username
        db.session.commit()
        health_columns = {
            column["name"] for column in inspect(db.engine).get_columns("health_checks")
        }
        health_additions = {
            "entry_count": "INTEGER",
            "failure_streak": "INTEGER NOT NULL DEFAULT 0",
            "incident_open": "BOOLEAN NOT NULL DEFAULT 0",
            "last_alert_at": "DATETIME",
        }
        for name, definition in health_additions.items():
            if name in health_columns:
                continue
            try:
                with db.engine.begin() as connection:
                    connection.execute(
                        text(f"ALTER TABLE health_checks ADD COLUMN {name} {definition}")
                    )
            except OperationalError as exc:
                if "duplicate column name" not in str(exc).lower():
                    raise
        default_roles = [
            ("super_admin", "Super Admin", "Acesso total ao portal.", ["*"]),
            ("admin", "Administrador", "Gerencia empresas, blocos e aprovações.", ["admin.access", "content.edit", "approvals.review", "monitoring.run"]),
            ("editor", "Técnico", "Propõe alterações sujeitas a aprovação.", ["content.edit"]),
        ]
        for code, name, description, permissions in default_roles:
            role = Role.query.filter_by(code=code).first()
            if not role:
                candidate = Role(code=code, name=name, description=description, system=True)
                db.session.add(candidate)
                try:
                    db.session.flush()
                    role = candidate
                except IntegrityError:
                    db.session.rollback()
                    role = Role.query.filter_by(code=code).first()
            if not role:
                raise RuntimeError(f"Não foi possível inicializar o perfil {code}.")
            role.name = name
            role.description = description
            role.permissions = json.dumps(permissions, separators=(",", ":"))
            role.system = True
        application_defaults = [
            ("geofeed_public", "Geofeed público", "Feed aprovado e downloads públicos.", True, 10),
            ("admin_center", "Admin Center", "Administração do Geofeed e da suíte.", False, 20),
            ("isp_network_health", "ISP Network Health", "Diagnósticos de reputação e rede.", False, 30),
        ]
        for code, name, description, public, sort_order in application_defaults:
            application = Application.query.filter_by(code=code).first()
            if not application:
                application = Application(code=code, name=name, description=description)
                db.session.add(application)
            application.name = name
            application.description = description
            application.public = public
            application.active = True
            application.sort_order = sort_order
        for name in ("Infraestrutura", "Redes", "Telefonia"):
            if not Sector.query.filter_by(name=name).first():
                candidate = Sector(name=name)
                db.session.add(candidate)
                try:
                    db.session.flush()
                except IntegrityError:
                    db.session.rollback()
        db.session.commit()

    from .settings import get_setting
    with app.app_context():
        tenant = get_setting("entra.tenant_id", app.config.get("ENTRA_TENANT_ID"))
        client_id = get_setting("entra.client_id", app.config.get("ENTRA_CLIENT_ID"))
        client_secret = get_setting("entra.client_secret", app.config.get("ENTRA_CLIENT_SECRET"))
        google_client_id = get_setting("google.client_id", app.config.get("GOOGLE_CLIENT_ID"))
        google_client_secret = get_setting("google.client_secret", app.config.get("GOOGLE_CLIENT_SECRET"))
    if tenant and client_id and client_secret:
        oauth.register(
            name="entra",
            client_id=client_id,
            client_secret=client_secret,
            server_metadata_url=(
                f"https://login.microsoftonline.com/{tenant}/v2.0/"
                ".well-known/openid-configuration"
            ),
            client_kwargs={
                "scope": "openid profile email"
                + (" User.Read" if app.config.get("GRAPH_PHOTO_ENABLED") else "")
            },
            token_endpoint_auth_method="client_secret_post",  # nosec B106
        )
    if google_client_id and google_client_secret:
        oauth.register(
            name="google",
            client_id=google_client_id,
            client_secret=google_client_secret,
            server_metadata_url="https://accounts.google.com/.well-known/openid-configuration",
            client_kwargs={"scope": "openid email profile"},
        )

    from .auth import bp as auth_bp
    from .routes import bp as routes_bp

    app.register_blueprint(auth_bp)
    app.register_blueprint(routes_bp)

    @app.before_request
    def restore_session_from_cookie():
        restore_remembered_session()

    from .commands import register_commands

    register_commands(app)

    @app.context_processor
    def inject_globals():
        from .settings import get_setting
        user = current_user()
        def safe_color(value: str | None, fallback: str) -> str:
            return value if value and re.fullmatch(r"#[0-9a-fA-F]{6}", value) else fallback

        unread_notifications = 0
        if user:
            unread_notifications = InAppNotification.query.filter_by(
                user_id=user.id, read_at=None
            ).count()
        return {
            "current_user": user,
            "unread_notifications": unread_notifications,
            "current_user_avatar": (
                url_for("panel.user_avatar", user_id=user.id)
                if user and ((Path(app.config["AVATAR_ROOT"]) / (user.avatar_path or f"{user.id}.jpg")).is_file() or user.avatar_kind in {"preset", "custom", "builder"} or user.avatar_kind in AVATAR_PRESETS)
                else ""
            ),
            "avatar_presets": AVATAR_PRESETS,
            "avatar_preset_urls": {
                key: url_for("panel.avatar_preset", preset=key)
                for key in AVATAR_PRESET_CONFIGS
            },
            "avatar_preset_data_urls": {
                key: "data:image/svg+xml;base64," + base64.b64encode(avatar_svg(config).encode()).decode()
                for key, config in AVATAR_PRESET_CONFIGS.items()
            },
            "dicebear_catalog": dicebear_catalog(),
            "local_auth_enabled": get_setting("auth.local_enabled", str(app.config.get("LOCAL_AUTH_ENABLED", True))) == "True",
            "role_names": {role.code: role.name for role in Role.query.filter_by(active=True).all()},
            "portal_branding": {
                "company_name": (get_setting("branding.company_name", app.config.get("COMPANY_NAME", "Sua empresa")) or app.config.get("COMPANY_NAME", "Sua empresa"))[:120],
                "suite_name": (get_setting("branding.suite_name", app.config.get("SUITE_NAME", "ISP Network Tools")) or app.config.get("SUITE_NAME", "ISP Network Tools"))[:120],
                "primary": safe_color(get_setting("branding.primary", "#5619a3"), "#5619a3"),
                "secondary": safe_color(get_setting("branding.secondary", "#7c32c7"), "#7c32c7"),
                "accent": safe_color(get_setting("branding.accent", "#b786f4"), "#b786f4"),
                "background_start": safe_color(get_setting("branding.background_start", "#09070d"), "#09070d"),
                "background_end": safe_color(get_setting("branding.background_end", "#180d2c"), "#180d2c"),
                "gradient": get_setting("branding.gradient", "True") == "True",
            },
            "suite_applications": [
                {
                    "code": application.code,
                    "name": application.name,
                    "description": application.description,
                    "url": {
                        "geofeed_public": app.config.get("PUBLIC_BASE_URL"),
                        "admin_center": url_for("panel.settings") if user and user.is_super_admin() else app.config.get("ADMIN_BASE_URL"),
                        "isp_network_health": url_for("panel.issue_sso", target="isp_network_health") if user else app.config.get("HEALTH_BASE_URL"),
                    }.get(application.code, application.url),
                    "available": (
                        application.public
                        or bool(user and user.has_application_access(application.code))
                    ),
                }
                for application in Application.query.filter_by(active=True).order_by(Application.sort_order, Application.name).all()
                if application.public or user
            ],
        }

    @app.get("/internal/health")
    @limiter.exempt
    def internal_health():
        return jsonify({"status": "ok"})

    @app.after_request
    def security_headers(response):
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; base-uri 'none'; object-src 'none'; "
            "frame-ancestors 'none'; form-action 'self'; img-src 'self' data: blob: https://*.tile.openstreetmap.org; "
            "style-src 'self'; style-src-attr 'unsafe-inline'; script-src 'self'; connect-src 'self'"
        )
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        # Keep the CSRF same-origin referrer check compatible with HTTPS forms
        # without sending the admin URL to external origins.
        response.headers["Referrer-Policy"] = "origin"
        response.headers["Permissions-Policy"] = (
            "camera=(), microphone=(), geolocation=(), payment=(), usb=()"
        )
        response.headers["Cross-Origin-Opener-Policy"] = "same-origin"
        response.headers["Cross-Origin-Resource-Policy"] = "same-origin"
        response.headers["Cache-Control"] = "no-store"
        if app.config.get("APP_ENV") == "production":
            response.headers["Strict-Transport-Security"] = (
                "max-age=31536000; includeSubDomains"
            )
        cookie_name = app.config["REMEMBER_COOKIE_NAME"]
        cookie_options = {
            "httponly": True,
            "secure": bool(app.config.get("SESSION_COOKIE_SECURE")),
            "samesite": "Lax",
            "path": "/",
        }
        if getattr(g, "expire_remember_cookie", False):
            response.delete_cookie(cookie_name, **cookie_options)
        elif getattr(g, "remember_cookie_value", ""):
            response.set_cookie(
                cookie_name,
                g.remember_cookie_value,
                max_age=app.config["REMEMBER_COOKIE_DAYS"] * 24 * 60 * 60,
                **cookie_options,
            )
        return response

    @app.errorhandler(400)
    def bad_request(_error):
        return render_template("error.html", code=400, message="Requisição inválida ou expirada."), 400

    @app.errorhandler(401)
    def unauthorized(_error):
        if request.path.startswith("/auth/"):
            return render_template("error.html", code=401, message="Acesso não autorizado."), 401
        return redirect(url_for("auth.login"))

    @app.errorhandler(403)
    def forbidden(_error):
        return render_template("error.html", code=403, message="Você não tem permissão para esta operação."), 403

    @app.errorhandler(404)
    def not_found(_error):
        return render_template("error.html", code=404, message="Página não encontrada."), 404

    @app.errorhandler(413)
    def too_large(_error):
        return render_template("error.html", code=413, message="Arquivo maior que o limite permitido."), 413

    @app.errorhandler(409)
    def conflict(_error):
        return render_template("error.html", code=409, message="A operação não é compatível com o estado atual."), 409

    @app.errorhandler(503)
    def unavailable(_error):
        return render_template("error.html", code=503, message="Serviço temporariamente indisponível."), 503

    @app.errorhandler(429)
    def too_many(_error):
        return render_template("error.html", code=429, message="Muitas requisições. Tente novamente em instantes."), 429

    @app.errorhandler(500)
    def server_error(_error):
        db.session.rollback()
        return render_template("error.html", code=500, message="Ocorreu um erro interno. A operação não foi concluída."), 500

    return app
