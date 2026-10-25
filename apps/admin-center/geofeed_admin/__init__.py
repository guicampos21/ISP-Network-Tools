from __future__ import annotations

import os
import json
import re
import base64
from datetime import timedelta
from pathlib import Path

from authlib.integrations.flask_client import OAuth
from flask import Flask, g, jsonify, redirect, render_template, request, url_for
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_wtf.csrf import CSRFProtect
from sqlalchemy import event, inspect, text
from sqlalchemy.engine import Engine
from sqlalchemy.exc import IntegrityError, OperationalError, ProgrammingError
from werkzeug.middleware.proxy_fix import ProxyFix

from .config import Config
from .models import Application, InAppNotification, JobFunction, Role, Sector, ServiceCatalogItem, User, db, utcnow
from .avatar import AVATAR_PRESET_CONFIGS, AVATAR_PRESETS, avatar_svg, dicebear_catalog
from .security import current_user, restore_remembered_session
from isp_shared.assets import register_suite_assets


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


def _rename_legacy_master_tables(connection) -> None:
    """Move the first IPAM registries to their Admin Center names."""
    tables = set(inspect(connection).get_table_names())
    for legacy_name, canonical_name in (
        ("ipam_customers", "customers"),
        ("ipam_pops", "pops_dcs"),
    ):
        if legacy_name in tables and canonical_name not in tables:
            connection.execute(text(f"ALTER TABLE {legacy_name} RENAME TO {canonical_name}"))
            tables.remove(legacy_name)
            tables.add(canonical_name)


def create_app(test_config: dict | None = None) -> Flask:
    app = Flask(__name__)
    register_suite_assets(app)
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
        migration_lock_connection = None
        if str(app.config.get("SQLALCHEMY_DATABASE_URI", "")).startswith("postgresql"):
            # The web process and the worker both create the application at boot.
            # Hold one PostgreSQL session lock across the complete additive
            # migration so index/column DDL cannot deadlock during a rollout.
            migration_lock_connection = db.engine.connect()
            migration_lock_connection.execute(
                text("SELECT pg_advisory_lock(hashtext('isp-network-tools-schema-migration'))")
            )
            migration_lock_connection.commit()
        try:
            if str(app.config.get("SQLALCHEMY_DATABASE_URI", "")).startswith("postgresql"):
                with db.engine.begin() as connection:
                    connection.execute(
                        text("SELECT pg_advisory_xact_lock(hashtext('isp-network-tools-admin-schema'))")
                    )
                    _rename_legacy_master_tables(connection)
                    db.metadata.create_all(bind=connection)
            else:
                with db.engine.begin() as connection:
                    _rename_legacy_master_tables(connection)
                    db.metadata.create_all(bind=connection)
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
        if str(app.config.get("SQLALCHEMY_DATABASE_URI", "")).startswith("postgresql"):
            with db.engine.begin() as connection:
                connection.execute(
                    text("ALTER TABLE users ADD COLUMN IF NOT EXISTS last_seen_at TIMESTAMPTZ")
                )
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
            "last_seen_at": "DATETIME",
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
            connection.execute(
                text("CREATE INDEX IF NOT EXISTS ix_users_last_seen_at ON users(last_seen_at)")
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
        # Additive migrations for the shared Admin Center registries. The
        # original installation used a few text fields; they remain in the
        # schema for compatibility while new screens use the structured data.
        registry_additions = {
            "companies": {
                "cnpj": "VARCHAR(18) NOT NULL DEFAULT ''",
                "address": "VARCHAR(255) NOT NULL DEFAULT ''",
                "latitude": "NUMERIC(10, 7)",
                "longitude": "NUMERIC(10, 7)",
                "contact_phone": "VARCHAR(64) NOT NULL DEFAULT ''",
            },
            "customers": {
                "cnpj": "VARCHAR(18) NOT NULL DEFAULT ''",
                "latitude": "NUMERIC(10, 7)",
                "longitude": "NUMERIC(10, 7)",
            },
            "customer_service_items": {
                "status": "VARCHAR(16) NOT NULL DEFAULT 'active'",
            },
            "pops_dcs": {
                "access_24h": "BOOLEAN NOT NULL DEFAULT FALSE",
                "battery_autonomy_minutes": "INTEGER NOT NULL DEFAULT 0",
                "primary_edge_router_id": "INTEGER REFERENCES ipam_equipments(id) ON DELETE SET NULL",
            },
            "ipam_allocations": {
                "parent_id": "INTEGER REFERENCES ipam_allocations(id) ON DELETE RESTRICT",
                "company_id": "INTEGER REFERENCES companies(id) ON DELETE RESTRICT",
                "geofeed_region": "VARCHAR(16) NOT NULL DEFAULT ''",
                "approval_status": "VARCHAR(16) NOT NULL DEFAULT 'approved'",
                "equipment_id": "INTEGER REFERENCES ipam_equipments(id) ON DELETE SET NULL",
                "router_id": "INTEGER REFERENCES ipam_equipments(id) ON DELETE SET NULL",
                "cpe_id": "INTEGER REFERENCES ipam_equipments(id) ON DELETE SET NULL",
                "access_type": "VARCHAR(16) NOT NULL DEFAULT 'fiber'",
                "access_type_2": "VARCHAR(16) NOT NULL DEFAULT 'fiber'",
                "pop_2_id": "INTEGER REFERENCES pops_dcs(id) ON DELETE SET NULL",
                "router_2_id": "INTEGER REFERENCES ipam_equipments(id) ON DELETE SET NULL",
                "switch_id": "INTEGER REFERENCES ipam_equipments(id) ON DELETE SET NULL",
                "switch_2_id": "INTEGER REFERENCES ipam_equipments(id) ON DELETE SET NULL",
                "access_point_id": "INTEGER REFERENCES ipam_equipments(id) ON DELETE SET NULL",
                "access_point_2_id": "INTEGER REFERENCES ipam_equipments(id) ON DELETE SET NULL",
                "st_id": "INTEGER REFERENCES ipam_equipments(id) ON DELETE SET NULL",
                "st_2_id": "INTEGER REFERENCES ipam_equipments(id) ON DELETE SET NULL",
                "metadata_incomplete": "BOOLEAN NOT NULL DEFAULT FALSE",
                "metadata_warning": "VARCHAR(255) NOT NULL DEFAULT ''",
            },
            "ipam_equipments": {
                "equipment_type": "VARCHAR(16) NOT NULL DEFAULT 'other'",
                "pop_id": "INTEGER REFERENCES pops_dcs(id) ON DELETE SET NULL",
                "secondary_pop_id": "INTEGER REFERENCES pops_dcs(id) ON DELETE SET NULL",
                "customer_id": "INTEGER REFERENCES customers(id) ON DELETE SET NULL",
                "router_id": "INTEGER REFERENCES ipam_equipments(id) ON DELETE SET NULL",
                "secondary_router_id": "INTEGER REFERENCES ipam_equipments(id) ON DELETE SET NULL",
                "cpe_id": "INTEGER REFERENCES ipam_equipments(id) ON DELETE SET NULL",
                "access_point_id": "INTEGER REFERENCES ipam_equipments(id) ON DELETE SET NULL",
            },
        }
        for table_name, table_additions in registry_additions.items():
            existing_columns = {column["name"] for column in inspect(db.engine).get_columns(table_name)}
            for name, definition in table_additions.items():
                if name in existing_columns:
                    continue
                try:
                    with db.engine.begin() as connection:
                        connection.execute(text(f"ALTER TABLE {table_name} ADD COLUMN {name} {definition}"))
                except (OperationalError, ProgrammingError) as exc:
                    sqlstate = getattr(getattr(exc, "orig", None), "sqlstate", "")
                    duplicate_column = sqlstate == "42701" or "duplicate column name" in str(exc).lower()
                    if not duplicate_column and "already exists" not in str(exc).lower():
                        raise
        # Carry forward the former customer document when it was already
        # populated. Empty values are intentionally allowed only for legacy
        # rows; all new forms require a validated CNPJ.
        with db.engine.begin() as connection:
            connection.execute(text("UPDATE customers SET cnpj = document WHERE cnpj = '' AND document <> ''"))
            connection.execute(text("UPDATE customer_service_items SET status = 'active' WHERE status IS NULL OR status = ''"))
            connection.execute(text("UPDATE ipam_allocations SET router_id = equipment_id WHERE router_id IS NULL AND equipment_id IS NOT NULL"))
            # Recover unambiguous POP/customer context for legacy equipment.
            # Ambiguous records remain untouched so no assignment is guessed.
            connection.execute(text(
                "UPDATE ipam_equipments SET pop_id = ("
                "SELECT MIN(a.pop_id) FROM ipam_allocations a "
                "WHERE (a.router_id = ipam_equipments.id OR a.equipment_id = ipam_equipments.id) "
                "AND a.pop_id IS NOT NULL"
                ") WHERE pop_id IS NULL AND ("
                "SELECT COUNT(DISTINCT a.pop_id) FROM ipam_allocations a "
                "WHERE (a.router_id = ipam_equipments.id OR a.equipment_id = ipam_equipments.id) "
                "AND a.pop_id IS NOT NULL"
                ") = 1"
            ))
            connection.execute(text(
                "UPDATE ipam_equipments SET customer_id = ("
                "SELECT MIN(a.customer_id) FROM ipam_allocations a "
                "WHERE (a.cpe_id = ipam_equipments.id OR a.equipment_id = ipam_equipments.id) "
                "AND a.customer_id IS NOT NULL"
                ") WHERE customer_id IS NULL AND equipment_type = 'cpe' AND ("
                "SELECT COUNT(DISTINCT a.customer_id) FROM ipam_allocations a "
                "WHERE (a.cpe_id = ipam_equipments.id OR a.equipment_id = ipam_equipments.id) "
                "AND a.customer_id IS NOT NULL"
                ") = 1"
            ))
            connection.execute(text("CREATE INDEX IF NOT EXISTS ix_ipam_allocations_router_id ON ipam_allocations(router_id)"))
            connection.execute(text("CREATE INDEX IF NOT EXISTS ix_ipam_allocations_cpe_id ON ipam_allocations(cpe_id)"))
            connection.execute(text("CREATE INDEX IF NOT EXISTS ix_ipam_equipments_equipment_type ON ipam_equipments(equipment_type)"))
            connection.execute(text("CREATE INDEX IF NOT EXISTS ix_ipam_equipments_pop_id ON ipam_equipments(pop_id)"))
            connection.execute(text("CREATE INDEX IF NOT EXISTS ix_ipam_equipments_customer_id ON ipam_equipments(customer_id)"))
            connection.execute(text("CREATE INDEX IF NOT EXISTS ix_ipam_allocations_pop_2_id ON ipam_allocations(pop_2_id)"))
            connection.execute(text("CREATE INDEX IF NOT EXISTS ix_ipam_allocations_router_2_id ON ipam_allocations(router_2_id)"))
            connection.execute(text("CREATE UNIQUE INDEX IF NOT EXISTS ix_companies_cnpj_nonempty ON companies(cnpj) WHERE cnpj <> ''"))
            connection.execute(text("CREATE UNIQUE INDEX IF NOT EXISTS ix_customers_cnpj_nonempty ON customers(cnpj) WHERE cnpj <> ''"))
            connection.execute(text("CREATE INDEX IF NOT EXISTS ix_ipam_allocations_equipment_id ON ipam_allocations(equipment_id)"))
            connection.execute(text("CREATE INDEX IF NOT EXISTS ix_ipam_allocations_geofeed_region ON ipam_allocations(geofeed_region)"))
            connection.execute(text("CREATE INDEX IF NOT EXISTS ix_ipam_allocations_metadata_incomplete ON ipam_allocations(metadata_incomplete)"))
            duplicate_users = connection.execute(text(
                "SELECT user_id FROM user_group_members GROUP BY user_id HAVING COUNT(*) > 1"
            )).scalars().all()
            for user_id in duplicate_users:
                keep = connection.execute(text(
                    "SELECT MIN(group_id) FROM user_group_members WHERE user_id = :user_id"
                ), {"user_id": user_id}).scalar_one()
                connection.execute(text(
                    "DELETE FROM user_group_members WHERE user_id = :user_id AND group_id <> :group_id"
                ), {"user_id": user_id, "group_id": keep})
            connection.execute(text(
                "CREATE UNIQUE INDEX IF NOT EXISTS ix_user_group_members_user_unique "
                "ON user_group_members(user_id)"
            ))
        default_roles = [
            ("super_admin", "Super Admin", "Acesso total ao portal.", ["*"]),
            ("admin", "Administrador", "Gerencia cadastros mestres, blocos e aprovações.", [
                "app.admin_center.access", "app.ipam_geofeed.access", "app.isp_network_health.access",
                "dashboard.view", "audit.view", "admin.access", "content.edit", "approvals.review", "monitoring.run",
                "catalog.companies.view", "catalog.companies.manage",
                "catalog.customers.view", "catalog.customers.manage",
                "catalog.pops.view", "catalog.pops.manage",
                "catalog.services.view", "catalog.services.manage",
                "ipam.private.manage", "ipam.public.submit", "ipam.public.approve", "ipam.public.reject", "ipam.equipment.manage", "ipam.publish",
                "health.view", "health.run", "health.report.export",
            ]),
            ("ipam_operator", "Operador IPAM", "Administra o inventário e envia recursos públicos para aprovação.", [
                "app.admin_center.access", "app.ipam_geofeed.access", "dashboard.view", "content.edit",
                "catalog.companies.view", "catalog.companies.manage",
                "catalog.customers.view", "catalog.customers.manage",
                "catalog.pops.view", "catalog.pops.manage",
                "catalog.services.view", "catalog.services.manage",
                "ipam.private.manage", "ipam.public.submit", "ipam.equipment.manage",
            ]),
            ("health_operator", "Operador Network Health", "Executa análises e consulta relatórios de saúde.", [
                "app.admin_center.access", "app.isp_network_health.access", "dashboard.view",
                "health.view", "health.run", "health.report.export",
            ]),
            ("viewer", "Consulta", "Acesso somente para leitura.", [
                "app.admin_center.access", "dashboard.view", "audit.view",
                "catalog.companies.view", "catalog.customers.view", "catalog.pops.view",
                "catalog.services.view", "health.view",
            ]),
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
        # Keep the legacy role code readable while moving existing users to
        # the profile that preserves the former editor workflow.
        db.session.execute(text("UPDATE users SET role = 'ipam_operator' WHERE role = 'editor'"))
        legacy_editor = Role.query.filter_by(code="editor").first()
        if legacy_editor:
            legacy_editor.active = False
        application_defaults = [
            ("geofeed_public", "Geofeed público", "Feed aprovado e downloads públicos.", True, 10),
            ("admin_center", "Admin Center", "Visão geral, auditoria e configurações da suíte.", False, 20),
            ("ipam_geofeed", "IPAM/Geofeed", "Inventário IP, alocações e publicação Geofeed.", False, 30),
            ("isp_network_health", "ISP Network Health", "Diagnósticos de reputação e rede.", False, 40),
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
        service_defaults = []
        bandwidths = ("50 Mb/s", "100 Mb/s", "200 Mb/s", "400 Mb/s", "500 Mb/s", "1 Gb/s")
        for service_type, prefix in (
            ("Link IP", "Link IP"),
            ("MPLS/L2L", "MPLS/L2L"),
            ("Port de Capacidade Agregada", "Port de Capacidade Agregada (Link IP + MPLS)"),
        ):
            for bandwidth in bandwidths:
                service_defaults.append((f"{prefix} {bandwidth}", service_type, bandwidth))
        for bandwidth in bandwidths:
            service_defaults.append((f"Link IP {bandwidth} · Segunda abordagem", "Link IP", f"{bandwidth} · Segunda abordagem"))
        for model in ("40", "60", "100", "200", "400"):
            for license_name in ("Standard", "Enterprise", "UTP"):
                service_defaults.append((f"Firewall Fortigate {model} · Licença {license_name}", "Firewall", f"Fortigate {model} · {license_name}"))
        service_defaults.extend((
            ("Backup gerenciado", "Serviço gerenciado", ""),
            ("Cloud Privada", "Cloud", ""),
            ("Colocation", "Datacenter", ""),
            ("Cloud Connect", "Cloud", ""),
        ))
        for service_name, service_type, specification in service_defaults:
            code = re.sub(r"[^a-z0-9]+", "-", service_name.casefold()).strip("-")[:80]
            if not ServiceCatalogItem.query.filter_by(code=code).first():
                db.session.add(ServiceCatalogItem(
                    code=code,
                    name=service_name,
                    service_type=service_type,
                    specification=specification,
                    active=True,
                ))
        db.session.commit()

        if migration_lock_connection is not None:
            try:
                migration_lock_connection.execute(
                    text("SELECT pg_advisory_unlock(hashtext('isp-network-tools-schema-migration'))")
                )
                migration_lock_connection.commit()
            finally:
                migration_lock_connection.close()

    from .settings import get_setting
    with app.app_context():
        tenant = get_setting("entra.tenant_id", app.config.get("ENTRA_TENANT_ID"))
        client_id = get_setting("entra.client_id", app.config.get("ENTRA_CLIENT_ID"))
        client_secret = get_setting("entra.client_secret", app.config.get("ENTRA_CLIENT_SECRET"))
        google_client_id = get_setting("google.client_id", app.config.get("GOOGLE_CLIENT_ID"))
        google_client_secret = get_setting("google.client_secret", app.config.get("GOOGLE_CLIENT_SECRET"))
        # OIDC settings may be stored in the database so an imported
        # installation does not need to duplicate non-secret identity
        # settings in its environment. Keep the Flask config in sync because
        # the callback validates the tenant against it.
        app.config["ENTRA_TENANT_ID"] = tenant or app.config.get("ENTRA_TENANT_ID", "")
        app.config["ENTRA_CLIENT_ID"] = client_id or app.config.get("ENTRA_CLIENT_ID", "")
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

    @app.before_request
    def track_user_presence():
        """Keep a lightweight presence signal for the operational dashboard."""
        if not request.endpoint or not request.endpoint.startswith("panel."):
            return
        user = current_user()
        if not user:
            return
        now = utcnow()
        last_seen = user.last_seen_at
        if last_seen is not None and last_seen.tzinfo is None:
            last_seen = last_seen.replace(tzinfo=now.tzinfo)
        if last_seen is None or now - last_seen >= timedelta(seconds=45):
            user.last_seen_at = now
            db.session.commit()

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
                        "admin_center": url_for("panel.dashboard") if user else app.config.get("ADMIN_BASE_URL"),
                        "ipam_geofeed": url_for("panel.ipam") if user else f"{app.config.get('ADMIN_BASE_URL', '').rstrip('/')}/ipam",
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
