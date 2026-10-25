from __future__ import annotations

import json
import ipaddress
import sqlite3
import time
from datetime import datetime, timezone
from pathlib import Path

import click
from apscheduler.schedulers.background import BackgroundScheduler
from flask import current_app
from sqlalchemy import text

from .geofeed import build_snapshot, parse_csv, validate_snapshot
from .models import (
    Application,
    AuditLog,
    ChangeRequest,
    Company,
    FeedEntry,
    HealthCheck,
    InAppNotification,
    IpamAllocation,
    NetworkBlock,
    NotificationLog,
    PortalSetting,
    PortalTheme,
    Publication,
    Role,
    User,
    db,
)
from .operations import periodic_healthcheck_due, process_scheduled, publish, run_healthchecks
from .settings import get_setting


SEED_BLOCKS = [
    ("168.90.48.0/22", "primary", 265264, "geofeed168.csv"),
    ("187.95.128.0/22", "primary", 265264, "geofeed187.csv"),
    ("2804:2d28::/32", "primary", 265264, "geofeed2d28.csv"),
    ("200.169.64.0/21", "primary", 52976, "geofeed200.csv"),
    ("2804:420::/32", "primary", 52976, "geofeed420.csv"),
    ("2804:865c::/32", "primary", 272638, "geofeed865c.csv"),
]


def _legacy_datetime(value):
    if not value:
        return None
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    raw = str(value).strip().replace("Z", "+00:00")
    try:
        parsed = datetime.fromisoformat(raw)
    except ValueError:
        for fmt in ("%Y-%m-%d %H:%M:%S.%f", "%Y-%m-%d %H:%M:%S"):
            try:
                parsed = datetime.strptime(raw, fmt)
                break
            except ValueError:
                parsed = None
        if parsed is None:
            return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def _legacy_row(row, name, default=None):
    return row[name] if name in row.keys() else default


def _legacy_rows(source: sqlite3.Connection, table: str) -> list[sqlite3.Row]:
    tables = {
        item[0] for item in source.execute(
            "SELECT name FROM sqlite_master WHERE type = 'table'"
        ).fetchall()
    }
    if table not in tables:
        return []
    return source.execute(f'SELECT * FROM "{table}"').fetchall()


def _legacy_id_map(rows, key):
    return {int(row["id"]): key(row) for row in rows if row["id"] is not None}


def _legacy_int(value, default=None):
    """Normalize SQLite integer-looking foreign keys before map lookups."""
    try:
        return int(value) if value is not None else default
    except (TypeError, ValueError):
        return default


def _reset_postgres_sequences() -> None:
    """Move imported PostgreSQL sequences past explicit legacy IDs."""
    if not str(current_app.config.get("SQLALCHEMY_DATABASE_URI", "")).startswith("postgresql"):
        return
    tables = (
        "users", "roles", "groups", "applications", "sectors", "job_functions",
        "session_tokens", "portal_settings", "portal_themes", "companies",
        "network_blocks", "feed_entries", "customers", "service_catalog_items",
        "pops_dcs", "pop_access_windows", "ipam_allocations",
        "ipam_approval_requests", "change_requests", "publications", "audit_logs",
        "health_checks", "notification_logs", "in_app_notifications",
    )
    for table in tables:
        db.session.execute(
            text(
                f"""
                SELECT setval(
                    pg_get_serial_sequence('{table}', 'id'),
                    GREATEST(COALESCE((SELECT MAX(id) FROM \"{table}\"), 0), 1),
                    (SELECT COUNT(*) FROM \"{table}\") > 0
                )
                """
            )
        )


def _import_legacy_sqlite(source_path: Path, *, apply_changes: bool) -> dict[str, int]:
    """Import the legacy Geofeed SQLite database without importing secrets.

    The source is read-only from this process. The target is the Admin Center
    PostgreSQL database represented by the current SQLAlchemy models. Public
    files and the Entra client secret are handled separately by deployment.
    """
    if not source_path.is_file():
        raise click.ClickException(f"Arquivo SQLite ausente: {source_path}")
    source = sqlite3.connect(f"file:{source_path.resolve()}?mode=ro", uri=True)
    source.row_factory = sqlite3.Row
    try:
        table_names = {
            item[0] for item in source.execute(
                "SELECT name FROM sqlite_master WHERE type = 'table'"
            ).fetchall()
        }
        counts = {
            table: len(_legacy_rows(source, table))
            for table in (
                "roles", "users", "companies", "network_blocks", "feed_entries",
                "publications", "change_requests", "audit_logs", "health_checks",
                "portal_settings", "portal_themes", "notification_logs",
                "in_app_notifications",
            )
            if table in table_names
        }
        if not apply_changes:
            return counts

        role_map = {}
        role_codes = {role.code: role for role in Role.query.all()}
        for row in _legacy_rows(source, "roles"):
            legacy_code = str(row["code"] or "").strip()
            target_code = {"editor": "ipam_operator"}.get(legacy_code, legacy_code)
            if not target_code:
                continue
            role = role_codes.get(target_code)
            if not role:
                role = Role(
                    code=target_code[:64],
                    name=str(row["name"] or target_code)[:80],
                    description=str(row["description"] or "")[:255],
                    permissions=str(row["permissions"] or "[]"),
                    system=False,
                    active=bool(row["active"] if "active" in row.keys() else True),
                )
                db.session.add(role)
                db.session.flush()
                role_codes[target_code] = role
            role_map[int(row["id"])] = role.code

        user_map = {}
        for row in _legacy_rows(source, "users"):
            email = str(row["email"] or "").strip().casefold()
            if not email:
                continue
            user = User.query.filter_by(email=email).first()
            role = role_map.get(_legacy_int(row["role_id"])) if "role_id" in row.keys() and row["role_id"] else None
            role = role or {"editor": "ipam_operator"}.get(str(row["role"] or ""), str(row["role"] or "ipam_operator"))
            if not Role.query.filter_by(code=role, active=True).first():
                role = "viewer"
            if not user:
                user = User(email=email)
                db.session.add(user)
            user.display_name = str(_legacy_row(row, "display_name", "") or "")[:160]
            user.first_name = str(_legacy_row(row, "first_name", "") or "")[:80]
            user.last_name = str(_legacy_row(row, "last_name", "") or "")[:80]
            user.nickname = str(_legacy_row(row, "nickname", "") or "")[:80]
            user.department = str(_legacy_row(row, "department", "") or "")[:120]
            user.job_title = str(_legacy_row(row, "job_title", "") or "")[:120]
            user.auth_provider = str(_legacy_row(row, "auth_provider", "m365") or "m365")[:16]
            user.entra_oid = _legacy_row(row, "entra_oid")
            user.google_sub = _legacy_row(row, "google_sub")
            user.tenant_id = _legacy_row(row, "tenant_id")
            user.role = role[:16]
            user.active = bool(_legacy_row(row, "active", True))
            user.password_hash = _legacy_row(row, "password_hash") if user.auth_provider == "local" else None
            user.created_at = _legacy_datetime(_legacy_row(row, "created_at")) or user.created_at
            user.updated_at = _legacy_datetime(_legacy_row(row, "updated_at")) or user.updated_at
            db.session.flush()
            user_map[int(row["id"])] = user.id

        company_map = {}
        for row in _legacy_rows(source, "companies"):
            name = str(row["name"] or "").strip()
            if not name:
                continue
            company = Company.query.filter_by(name=name).first()
            if not company:
                company = Company(name=name, default_asn=int(row["default_asn"] or 0))
                db.session.add(company)
            company.default_asn = int(row["default_asn"] or company.default_asn or 0)
            company.contact_email = str(_legacy_row(row, "contact_email", "") or "")[:254]
            company.active = bool(_legacy_row(row, "active", True))
            company.cnpj = str(_legacy_row(row, "cnpj", "") or "")[:18]
            company.address = str(_legacy_row(row, "address", "") or "")[:255]
            company.contact_phone = str(_legacy_row(row, "contact_phone", "") or "")[:64]
            db.session.flush()
            company_map[int(row["id"])] = company.id

        block_map = {}
        for row in _legacy_rows(source, "network_blocks"):
            cidr = str(row["cidr"] or "").strip()
            if not cidr:
                continue
            block = NetworkBlock.query.filter_by(cidr=cidr).first()
            if not block:
                block = NetworkBlock(cidr=cidr, ip_version=int(row["ip_version"] or 4), company_id=company_map[int(row["company_id"])], asn=int(row["asn"] or 0), filename=str(row["filename"] or cidr.replace("/", "-")).lower()[:128])
                db.session.add(block)
            block.ip_version = int(row["ip_version"] or block.ip_version)
            block.company_id = company_map.get(int(row["company_id"]), block.company_id)
            block.asn = int(row["asn"] or block.asn or 0)
            block.filename = str(row["filename"] or block.filename).lower()[:128]
            block.description = str(_legacy_row(row, "description", "") or "")[:255]
            block.active = bool(_legacy_row(row, "active", True))
            db.session.flush()
            block_map[int(row["id"])] = block.id

        for row in _legacy_rows(source, "feed_entries"):
            block_id = block_map.get(_legacy_int(row["block_id"]))
            prefix = str(row["prefix"] or "").strip()
            if not block_id or not prefix:
                continue
            entry = FeedEntry.query.filter_by(block_id=block_id, prefix=prefix).first()
            if not entry:
                entry = FeedEntry(block_id=block_id, prefix=prefix)
                db.session.add(entry)
            entry.alpha2code = str(_legacy_row(row, "alpha2code", "BR") or "BR")[:2]
            entry.region = str(_legacy_row(row, "region", "BR-PR") or "BR-PR")[:16]
            entry.city = str(_legacy_row(row, "city", "") or "")[:160]
            entry.postal_code = str(_legacy_row(row, "postal_code", "") or "")[:32]
            entry.sort_order = int(_legacy_row(row, "sort_order", 0) or 0)
            db.session.flush()

        change_map = {}
        for row in _legacy_rows(source, "change_requests"):
            source_id = int(row["id"])
            change = db.session.get(ChangeRequest, source_id)
            if not change:
                change = ChangeRequest(
                    id=source_id,
                    title=str(row["title"] or "Importação legada")[:180],
                    notes=str(_legacy_row(row, "notes", "") or "")[:4000],
                    status=str(_legacy_row(row, "status", "pending") or "pending")[:24],
                    snapshot_json=str(_legacy_row(row, "snapshot_json", "{}") or "{}"),
                    snapshot_hash=str(_legacy_row(row, "snapshot_hash", "") or "")[:64],
                    diff_text=str(_legacy_row(row, "diff_text", "") or ""),
                    requested_by_id=user_map.get(
                        _legacy_int(row["requested_by_id"]),
                        next(iter(user_map.values()), None),
                    ),
                )
                db.session.add(change)
            change_map[source_id] = change.id
        db.session.flush()

        for row in _legacy_rows(source, "publications"):
            version = int(row["version"])
            publication = Publication.query.filter_by(version=version).first()
            if not publication:
                publication = Publication(
                    version=version,
                    snapshot_json=str(row["snapshot_json"] or "{}"),
                    snapshot_hash=str(row["snapshot_hash"] or "")[:64],
                    summary=str(_legacy_row(row, "summary", "") or "")[:255],
                    archive_path=str(_legacy_row(row, "archive_path", "") or "")[:512],
                    published_by_id=user_map.get(
                        _legacy_int(row["published_by_id"]),
                        next(iter(user_map.values()), None),
                    ),
                    change_request_id=change_map.get(_legacy_int(_legacy_row(row, "change_request_id"))),
                )
                db.session.add(publication)
            publication.published_at = _legacy_datetime(_legacy_row(row, "published_at")) or publication.published_at

        for row in _legacy_rows(source, "health_checks"):
            checked_at = _legacy_datetime(_legacy_row(row, "checked_at"))
            target = str(_legacy_row(row, "target", "") or "")[:512]
            if not target:
                continue
            check = HealthCheck.query.filter_by(target=target, checked_at=checked_at).first() if checked_at else None
            if not check:
                check = HealthCheck(checked_at=checked_at or datetime.now(timezone.utc), target=target, ok=bool(_legacy_row(row, "ok", False)))
                db.session.add(check)
            check.http_status = _legacy_row(row, "http_status")
            check.response_ms = _legacy_row(row, "response_ms")
            check.content_hash = str(_legacy_row(row, "content_hash", "") or "")[:64]
            check.details = str(_legacy_row(row, "details", "") or "")[:8000]
            check.entry_count = _legacy_row(row, "entry_count")
            check.failure_streak = int(_legacy_row(row, "failure_streak", 0) or 0)
            check.incident_open = bool(_legacy_row(row, "incident_open", False))
            check.last_alert_at = _legacy_datetime(_legacy_row(row, "last_alert_at"))

        for row in _legacy_rows(source, "portal_settings"):
            # Secret values stay in deployment secret files. This also avoids
            # copying historic SMTP credentials or provider tokens.
            if bool(_legacy_row(row, "is_secret", False)):
                continue
            key = str(row["key"] or "").strip()[:120]
            if not key:
                continue
            setting = PortalSetting.query.filter_by(key=key).first()
            if not setting:
                setting = PortalSetting(key=key)
                db.session.add(setting)
            setting.value = str(_legacy_row(row, "value", "") or "")
            setting.is_secret = False
            setting.changed_by_id = user_map.get(_legacy_row(row, "changed_by_id"))

        for row in _legacy_rows(source, "portal_themes"):
            name = str(_legacy_row(row, "name", "") or "")[:120]
            if not name:
                continue
            theme = PortalTheme.query.filter_by(name=name).first()
            if not theme:
                theme = PortalTheme(name=name, config=str(_legacy_row(row, "config", "{}") or "{}"))
                db.session.add(theme)
            theme.config = str(_legacy_row(row, "config", "{}") or "{}")
            theme.created_by_id = user_map.get(_legacy_row(row, "created_by_id"))

        for row in _legacy_rows(source, "audit_logs"):
            source_id = int(row["id"])
            if db.session.get(AuditLog, source_id):
                continue
            db.session.add(AuditLog(
                id=source_id,
                created_at=_legacy_datetime(_legacy_row(row, "created_at")) or datetime.now(timezone.utc),
                user_id=user_map.get(_legacy_row(row, "user_id")),
                action=str(_legacy_row(row, "action", "legacy.import") or "legacy.import")[:80],
                entity_type=str(_legacy_row(row, "entity_type", "") or "")[:80],
                entity_id=str(_legacy_row(row, "entity_id", "") or "")[:80],
                details=str(_legacy_row(row, "details", "") or "")[:8000],
                source_ip=str(_legacy_row(row, "source_ip", "") or "")[:64],
            ))

        for row in _legacy_rows(source, "notification_logs"):
            source_id = int(row["id"])
            if not db.session.get(NotificationLog, source_id):
                db.session.add(NotificationLog(
                    id=source_id,
                    created_at=_legacy_datetime(_legacy_row(row, "created_at")) or datetime.now(timezone.utc),
                    recipient=str(_legacy_row(row, "recipient", "") or "")[:254],
                    subject=str(_legacy_row(row, "subject", "") or "")[:255],
                    status=str(_legacy_row(row, "status", "") or "")[:24],
                    details=str(_legacy_row(row, "details", "") or "")[:8000],
                ))

        for row in _legacy_rows(source, "in_app_notifications"):
            source_id = int(row["id"])
            user_id = user_map.get(_legacy_int(_legacy_row(row, "user_id")))
            if user_id and not db.session.get(InAppNotification, source_id):
                db.session.add(InAppNotification(
                    id=source_id,
                    created_at=_legacy_datetime(_legacy_row(row, "created_at")) or datetime.now(timezone.utc),
                    user_id=user_id,
                    title=str(_legacy_row(row, "title", "") or "")[:180],
                    message=str(_legacy_row(row, "message", "") or "")[:2000],
                    link=str(_legacy_row(row, "link", "") or "")[:512],
                    read_at=_legacy_datetime(_legacy_row(row, "read_at")),
                ))
        db.session.commit()
        _reset_postgres_sequences()
        db.session.commit()
        return counts
    except Exception:
        db.session.rollback()
        raise
    finally:
        source.close()


def _bootstrap_admin() -> None:
    email = current_app.config.get("ENTRA_INITIAL_ADMIN_EMAIL", "").strip().casefold()
    existing = User.query.filter_by(email=email).first() if email else None
    if existing and existing.role != "super_admin":
        existing.role = "super_admin"
        existing.active = True
        db.session.commit()
    elif email and not existing:
        db.session.add(
            User(email=email, display_name="Administrador inicial", role="super_admin", active=True)
        )
        db.session.commit()


def register_commands(app) -> None:
    @app.cli.command("import-geofeed-inventory")
    def import_geofeed_inventory():
        """Integra blocos já aprovados do Geofeed ao IPAM sem republicar arquivos."""
        from .routes import _classify_ipam_network

        created = 0
        for block in NetworkBlock.query.filter_by(active=True).order_by(NetworkBlock.id).all():
            network = ipaddress.ip_network(block.cidr, strict=False)
            if _classify_ipam_network(network) != "public":
                continue
            existing = IpamAllocation.query.filter_by(resource_kind="block", prefix=str(network)).first()
            if existing:
                continue
            allocation = IpamAllocation(
                resource_kind="block", prefix=str(network), scope="public",
                status="available", approval_status="approved",
                company_id=block.company_id, source_block_id=block.id,
                description=block.description,
                notes="Importado de bloco previamente aprovado no Geofeed; alocações operacionais não inferidas.",
            )
            db.session.add(allocation)
            db.session.flush()
            db.session.add(AuditLog(
                action="ipam.allocation.imported", entity_type="allocation",
                entity_id=str(allocation.id),
                details=json.dumps({"prefix": allocation.prefix, "source_block_id": block.id}, ensure_ascii=False),
            ))
            created += 1
        db.session.commit()
        click.echo(f"{created} bloco(s) integrado(s) ao IPAM. Arquivos públicos preservados.")

    @app.cli.command("import-legacy-sqlite")
    @click.option("--source", required=True, type=click.Path(exists=True, dir_okay=False, path_type=Path))
    @click.option("--apply", "apply_changes", is_flag=True, help="Grava a importação no PostgreSQL; sem esta opção apenas simula.")
    def import_legacy_sqlite(source: Path, apply_changes: bool):
        """Importa a base legada do Geofeed com proteção contra segredos."""
        counts = _import_legacy_sqlite(source, apply_changes=apply_changes)
        mode = "Importação gravada" if apply_changes else "Simulação concluída"
        click.echo(mode + ":")
        for table, count in counts.items():
            click.echo(f"  {table}: {count}")
        if not apply_changes:
            click.echo("Nenhuma alteração foi gravada. Use --apply após revisar os totais.")

    @app.cli.command("repair-ipam-hierarchy")
    @click.option("--apply", "apply_changes", is_flag=True, help="Grava os pais e filhos no IPAM; sem esta opção apenas simula.")
    def repair_ipam_hierarchy(apply_changes: bool):
        """Materializa filhos do Geofeed e garante uma hierarquia IPAM válida.

        A reparação é aditiva: não remove recursos nem altera os metadados
        operacionais já preenchidos. Pais criados apenas para estruturar a
        árvore ficam marcados para revisão cadastral.
        """
        from .routes import _classify_ipam_network

        roots = {
            block.id: allocation
            for allocation in IpamAllocation.query.filter(
                IpamAllocation.resource_kind == "block",
                IpamAllocation.parent_id.is_(None),
                IpamAllocation.status != "decommissioned",
            ).all()
            for block in [allocation.source_block] if allocation.source_block
        }
        # Include roots imported before source_block_id was available.
        for allocation in IpamAllocation.query.filter(
            IpamAllocation.resource_kind == "block",
            IpamAllocation.parent_id.is_(None),
            IpamAllocation.status != "decommissioned",
        ).all():
            roots.setdefault(
                next((block.id for block in NetworkBlock.query.filter_by(cidr=allocation.prefix).all()), None),
                allocation,
            )

        source_blocks = NetworkBlock.query.filter_by(active=True).order_by(NetworkBlock.id).all()
        entries = [entry for block in source_blocks for entry in block.entries]
        existing = {}
        for allocation in IpamAllocation.query.filter(IpamAllocation.status != "decommissioned").all():
            lookup_prefix = allocation.prefix
            if allocation.resource_kind == "ip":
                try:
                    lookup_prefix = str(ipaddress.ip_network(f"{allocation.prefix}/{ipaddress.ip_address(allocation.prefix).max_prefixlen}", strict=True))
                except ValueError:
                    pass
            existing.setdefault(lookup_prefix, allocation)

        structural: dict[tuple[int, str], ipaddress._BaseNetwork] = {}
        feed_items = []
        skipped = 0
        for entry in entries:
            try:
                network = ipaddress.ip_network(entry.prefix, strict=True)
                source_network = ipaddress.ip_network(entry.block.cidr, strict=False)
            except ValueError:
                skipped += 1
                continue
            if _classify_ipam_network(network) != "public" or not network.subnet_of(source_network):
                skipped += 1
                continue
            root = roots.get(entry.block_id)
            if not root:
                root = existing.get(str(source_network))
            if not root:
                skipped += 1
                continue
            root_network = ipaddress.ip_network(root.prefix, strict=True)
            if network == root_network:
                if apply_changes and entry.region and not root.geofeed_region:
                    root.geofeed_region = entry.region[:16]
                continue
            feed_items.append((entry, network, root))
            minimum = 24 if network.version == 4 else 32
            if network.prefixlen > minimum:
                parent_network = network.supernet(new_prefix=minimum)
                if parent_network != root_network and str(parent_network) not in existing:
                    structural[(entry.block_id, str(parent_network))] = parent_network

        created_structural = 0
        created_children = 0
        updated_links = 0
        if apply_changes:
            for (block_id, prefix), network in sorted(
                structural.items(), key=lambda item: (item[1].version, item[1].prefixlen, int(item[1].network_address))
            ):
                block = db.session.get(NetworkBlock, block_id)
                allocation = existing.get(prefix)
                if allocation:
                    continue
                allocation = IpamAllocation(
                    resource_kind="block",
                    prefix=prefix,
                    scope="public",
                    status="available",
                    approval_status="approved",
                    company_id=block.company_id,
                    source_block_id=block.id,
                    description="Bloco pai estrutural",
                    notes="Criado automaticamente para organizar recursos menores já presentes no Geofeed.",
                    geofeed_region="",
                    metadata_incomplete=True,
                    metadata_warning="Faltam informações cadastrais neste bloco pai.",
                )
                db.session.add(allocation)
                db.session.flush()
                existing[prefix] = allocation
                created_structural += 1

            for entry, network, root in sorted(feed_items, key=lambda item: (item[1].version, item[1].prefixlen, int(item[1].network_address))):
                prefix = str(network)
                allocation = existing.get(prefix)
                if allocation is None:
                    allocation = IpamAllocation(
                        resource_kind="ip" if network.prefixlen == network.max_prefixlen else "block",
                        prefix=prefix if network.prefixlen < network.max_prefixlen else str(network.network_address),
                        scope="public",
                        status="allocated",
                        approval_status="approved",
                        company_id=root.company_id,
                        source_block_id=entry.block_id,
                        geofeed_region=(entry.region or "")[:16],
                        description="Importado do último Geofeed publicado",
                        notes="Revise os dados operacionais deste recurso no IPAM.",
                    )
                    db.session.add(allocation)
                    db.session.flush()
                    existing[prefix] = allocation
                    # IP resources are stored without /32 in the application,
                    # but the lookup key remains canonical for hierarchy work.
                    if network.prefixlen == network.max_prefixlen:
                        existing[str(network.network_address)] = allocation
                    created_children += 1
                elif not allocation.geofeed_region and entry.region:
                    allocation.geofeed_region = entry.region[:16]

            all_allocations = list({item.id: item for item in existing.values() if isinstance(item, IpamAllocation)}.values())
            for allocation in all_allocations:
                try:
                    network = ipaddress.ip_network(
                        allocation.prefix,
                        strict=False,
                    )
                except ValueError:
                    continue
                if allocation.parent_id is not None:
                    continue
                parent_candidates = []
                for candidate in all_allocations:
                    if candidate.id == allocation.id or candidate.resource_kind != "block":
                        continue
                    try:
                        candidate_network = ipaddress.ip_network(candidate.prefix, strict=False)
                    except ValueError:
                        continue
                    if candidate_network.version == network.version and network.subnet_of(candidate_network) and candidate_network != network:
                        if candidate.company_id == allocation.company_id:
                            parent_candidates.append((candidate_network.prefixlen, candidate))
                if parent_candidates:
                    parent = max(parent_candidates, key=lambda item: item[0])[1]
                    if allocation.parent_id != parent.id:
                        allocation.parent = parent
                        allocation.parent_prefix = parent.prefix
                        updated_links += 1
            db.session.add(AuditLog(
                action="ipam.allocation.hierarchy_repaired",
                entity_type="ipam",
                entity_id="hierarchy",
                details=json.dumps({
                    "structural_parents": created_structural,
                    "geofeed_children": created_children,
                    "parent_links": updated_links,
                    "skipped": skipped,
                }, ensure_ascii=False),
            ))
            db.session.commit()

        mode = "Reparação gravada" if apply_changes else "Simulação concluída"
        missing_children = sum(1 for _entry, network, _root in feed_items if str(network) not in existing)
        click.echo(f"{mode}:")
        click.echo(f"  Pais estruturais a criar: {len(structural) if not apply_changes else created_structural}")
        click.echo(f"  Filhos do Geofeed a materializar: {missing_children if not apply_changes else created_children}")
        click.echo(f"  Itens ignorados: {skipped}")
        if apply_changes:
            click.echo(f"  Relações pai/filho ajustadas: {updated_links}")
        else:
            click.echo("Nenhuma alteração foi gravada. Use --apply após revisar os totais.")

    @app.cli.command("init-db")
    def init_db():
        """Cria o banco e o administrador inicial, sem publicar arquivos."""
        db.create_all()
        _bootstrap_admin()
        click.echo("Banco inicializado.")

    @app.cli.command("seed-current")
    @click.option("--csv-dir", required=True, type=click.Path(file_okay=False, path_type=Path))
    def seed_current(csv_dir: Path):
        """Importa os seis geofeeds existentes para uma base vazia."""
        db.create_all()
        _bootstrap_admin()
        if Company.query.count() or NetworkBlock.query.count():
            raise click.ClickException("A base já possui empresas ou blocos; seed recusado.")
        company_name = current_app.config.get("COMPANY_NAME", "Sua empresa").strip()[:120]
        companies: dict[str, Company] = {}
        for _cidr, name, asn, _filename in SEED_BLOCKS:
            if name not in companies:
                company = Company(
                    name=company_name if name == "primary" else name,
                    default_asn=asn,
                    contact_email=current_app.config.get("PUBLIC_CONTACT_EMAIL", ""),
                    active=True,
                )
                db.session.add(company)
                db.session.flush()
                companies[name] = company
        for cidr, name, asn, filename in SEED_BLOCKS:
            source = csv_dir / filename
            if not source.is_file():
                db.session.rollback()
                raise click.ClickException(f"Arquivo ausente: {source}")
            import ipaddress

            network = ipaddress.ip_network(cidr, strict=True)
            block = NetworkBlock(
                cidr=str(network),
                ip_version=network.version,
                company_id=companies[name].id,
                asn=asn,
                filename=filename,
                active=True,
            )
            db.session.add(block)
            db.session.flush()
            for item in parse_csv(source.read_bytes()):
                db.session.add(FeedEntry(block_id=block.id, **item))
        db.session.flush()
        validation = validate_snapshot(build_snapshot())
        if not validation.valid:
            db.session.rollback()
            raise click.ClickException("Seed inválido: " + " ".join(validation.errors))
        db.session.commit()
        click.echo(
            f"Importação concluída: {len(SEED_BLOCKS)} blocos; "
            f"{FeedEntry.query.count()} entradas."
        )

    @app.cli.command("validate-working")
    def validate_working():
        """Valida o estado de trabalho segundo RFC 8805 e regras internas."""
        validation = validate_snapshot(build_snapshot())
        for warning in validation.warnings:
            click.echo(f"AVISO: {warning}")
        for error in validation.errors:
            click.echo(f"ERRO: {error}")
        if not validation.valid:
            raise click.ClickException(f"{len(validation.errors)} erro(s) encontrado(s).")
        click.echo("Validação concluída sem erros.")

    @app.cli.command("publish-working")
    def publish_working():
        """Publica o estado de trabalho usando o primeiro administrador ativo."""
        db.create_all()
        publisher = User.query.filter(User.role.in_(["super_admin", "admin"]), User.active.is_(True)).order_by(User.id).first()
        if not publisher:
            raise click.ClickException("Nenhum administrador ativo cadastrado.")
        snapshot = build_snapshot()
        validation = validate_snapshot(snapshot)
        if not validation.valid:
            raise click.ClickException("Publicação recusada: " + " ".join(validation.errors))
        publication = publish(snapshot, publisher, "Importação inicial dos geofeeds atuais")
        db.session.commit()
        click.echo(f"Publicação v{publication.version} concluída.")

    @app.cli.command("run-worker")
    def run_worker():
        """Executa agendamentos e monitoramento em processo separado."""
        db.create_all()
        scheduler = BackgroundScheduler(timezone="UTC")

        def scheduled_job():
            with app.app_context():
                process_scheduled()

        def health_job():
            with app.app_context():
                if periodic_healthcheck_due():
                    run_healthchecks(trigger="periodic")

        scheduler.add_job(
            scheduled_job,
            "interval",
            minutes=1,
            id="scheduled-publications",
            max_instances=1,
            coalesce=True,
        )
        scheduler.add_job(
            health_job,
            "interval",
            minutes=1,
            id="public-healthchecks",
            max_instances=1,
            coalesce=True,
        )
        scheduler.start()
        click.echo("Worker iniciado.")
        try:
            while True:
                time.sleep(30)
        except (KeyboardInterrupt, SystemExit):
            scheduler.shutdown(wait=False)
