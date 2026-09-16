from __future__ import annotations

import io
import hashlib
import hmac
import ipaddress
import json
import re
import secrets
import zipfile
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import urlencode, urlparse
from zoneinfo import ZoneInfo, available_timezones

from email_validator import EmailNotValidError, validate_email
from flask import (
    Blueprint,
    abort,
    current_app,
    flash,
    redirect,
    render_template,
    Response,
    jsonify,
    request,
    send_file,
    url_for,
)
from sqlalchemy import func, or_
from sqlalchemy.exc import IntegrityError
from werkzeug.security import generate_password_hash
import requests

from . import limiter, oauth
from .avatar import (
    AVATAR_PRESETS,
    AVATAR_PRESET_CONFIGS,
    avatar_svg,
    clear_uploaded_avatar,
    dicebear_catalog,
    dicebear_svg,
    sanitize_avatar_config,
    sanitize_dicebear_config,
    store_uploaded_avatar,
)
from .geofeed import (
    build_snapshot,
    canonical_json,
    diff_snapshots,
    latest_published_snapshot,
    snapshot_hash,
    validate_snapshot,
    generate_csv,
)
from .models import (
    Application,
    AuditLog,
    ChangeRequest,
    Company,
    FeedEntry,
    Group,
    GroupApplicationGrant,
    HealthCheck,
    InAppNotification,
    NetworkBlock,
    NotificationLog,
    Publication,
    PortalTheme,
    Role,
    Sector,
    SessionToken,
    JobFunction,
    User,
    UserApplicationGrant,
    db,
    utcnow,
)
from .notifications import create_in_app_notifications, format_sender, send_notification, send_test_email, send_welcome_email, split_sender, test_smtp_connection
from .operations import (
    publish,
    rdap_check,
    replace_working_snapshot,
    run_healthchecks,
    run_publication_healthchecks,
)
from .security import audit, current_user, login_required, normalize_email, roles_required
from .settings import get_setting, set_setting, setting_info
from isp_shared.sso import issue_handoff


bp = Blueprint("panel", __name__)

PERMISSION_OPTIONS = {
    "content.edit": "Editar empresas, blocos e entradas",
    "approvals.review": "Aprovar ou rejeitar alterações",
    "monitoring.run": "Executar monitoramento",
    "admin.access": "Acessar recursos administrativos",
}


def _roles_for_form() -> list[Role]:
    return Role.query.filter_by(active=True).order_by(Role.system.desc(), Role.name).all()


def _role_names() -> dict[str, str]:
    return {role.code: role.name for role in Role.query.filter_by(active=True).all()}


def _sectors_for_form() -> list[Sector]:
    return Sector.query.filter_by(active=True).order_by(Sector.name).all()


def _functions_for_form() -> list[JobFunction]:
    return JobFunction.query.filter_by(active=True).order_by(JobFunction.name).all()


def _avatar_form_values(user: User | None) -> tuple[str, str]:
    kind = _clean(request.form.get("avatar_kind"), 32) if request.method == "POST" else (user.avatar_kind if user else "initials")
    config = request.form.get("avatar_config") if request.method == "POST" else (user.avatar_config if user else "{}")
    if kind in {"preset", "custom"}:
        return kind, json.dumps(sanitize_dicebear_config(config, kind), separators=(",", ":"))
    return kind, json.dumps(sanitize_avatar_config(config), separators=(",", ":"))


def _dicebear_form_values() -> tuple[str, str]:
    kind = _clean(request.form.get("avatar_kind"), 32)
    if kind not in {"preset", "custom"}:
        return kind, "{}"
    config = sanitize_dicebear_config(request.form.get("avatar_config"), kind)
    return kind, json.dumps(config, separators=(",", ":"))


class SubnetSuggestion(ValueError):
    def __init__(self, submitted: str, suggested: str):
        super().__init__(f"A sub-rede deve começar em {suggested}.")
        self.submitted = submitted
        self.suggested = suggested


def _clean(value: str | None, limit: int = 255) -> str:
    return (value or "").strip()[:limit]


def _integer(value: str | None, label: str, minimum: int = 1) -> int:
    try:
        number = int(value or "")
    except ValueError as exc:
        raise ValueError(f"{label} deve ser numérico.") from exc
    if number < minimum:
        raise ValueError(f"{label} inválido.")
    return number


def _network_input(value: str | None, form) -> tuple[ipaddress._BaseNetwork, str | None]:
    """Parse a CIDR and require its address to be the network boundary."""
    raw = _clean(value, 64)
    try:
        network = ipaddress.ip_network(raw, strict=True)
        return network, None
    except ValueError:
        try:
            suggested = ipaddress.ip_network(raw, strict=False)
        except ValueError:
            raise ValueError("CIDR inválido. Informe uma rede IPv4 ou IPv6 válida.")
        if form.get("accept_suggested_cidr") != "yes":
            raise SubnetSuggestion(raw, str(suggested))
        return suggested, None


def _block_review(block: NetworkBlock) -> list[str]:
    issues: list[str] = []
    try:
        ipaddress.ip_network(block.cidr, strict=True)
    except ValueError:
        try:
            suggested = ipaddress.ip_network(block.cidr, strict=False)
            issues.append(f"O bloco começa fora do limite da sub-rede; esperado: {suggested}.")
        except ValueError:
            issues.append("O bloco não contém um CIDR IPv4 ou IPv6 válido.")
    for entry in block.entries:
        try:
            ipaddress.ip_network(entry.prefix, strict=True)
        except ValueError:
            try:
                suggested = ipaddress.ip_network(entry.prefix, strict=False)
                issues.append(f"A entrada {entry.prefix} deveria começar em {suggested}.")
            except ValueError:
                issues.append(f"A entrada {entry.prefix} não é um CIDR válido.")
    return issues


def _email(value: str, required: bool = True) -> str:
    normalized = normalize_email(value)
    if not normalized and not required:
        return ""
    try:
        return validate_email(normalized, check_deliverability=False).normalized.casefold()
    except EmailNotValidError as exc:
        raise ValueError("E-mail inválido.") from exc


def _sender_from_form() -> tuple[str, str]:
    """Read the new sender fields, with compatibility for the former combined field."""
    name = _clean(request.form.get("smtp_from_name"), 120)
    address = _clean(request.form.get("smtp_from_address"), 255)
    legacy = _clean(request.form.get("smtp_from"), 255)
    if legacy:
        legacy_name, legacy_address = split_sender(legacy)
        name = name or legacy_name
        address = address or legacy_address or legacy
    if not address:
        legacy = get_setting("email.from", current_app.config.get("SMTP_FROM", ""))
        legacy_name, legacy_address = split_sender(legacy)
        name = name or get_setting("email.from_name", legacy_name) or legacy_name
        address = get_setting("email.from_address", legacy_address) or legacy_address or legacy
    return name, _email(address)


USERNAME_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{2,79}$")


def _username(value: str) -> str:
    username = _clean(value, 80).casefold()
    if not USERNAME_RE.fullmatch(username):
        raise ValueError("Username deve ter de 3 a 80 caracteres, usando letras minúsculas, números, ponto, hífen ou sublinhado.")
    return username


def _strong_password(value: str) -> None:
    if len(value) < 12 or not re.search(r"[A-Z]", value) or not re.search(r"[a-z]", value) or not re.search(r"\d", value) or not re.search(r"[^A-Za-z0-9]", value):
        raise ValueError("A senha deve ter ao menos 12 caracteres, maiúscula, minúscula, número e símbolo.")


def _commit_or_flash(success: str, redirect_endpoint: str, **values):
    try:
        db.session.commit()
        flash(success, "success")
    except IntegrityError:
        db.session.rollback()
        flash("Já existe um cadastro com esses dados.", "error")
    return redirect(url_for(redirect_endpoint, **values))


def _publish_or_flash(summary: str, redirect_endpoint: str, **values):
    """Publish the working snapshot immediately after an administrator mutation."""
    try:
        publication = publish(build_snapshot(), current_user(), summary)
        db.session.commit()
        run_publication_healthchecks()
        flash(f"{summary} Publicação v{publication.version} concluída.", "success")
    except IntegrityError:
        db.session.rollback()
        flash("Já existe um cadastro com esses dados.", "error")
    except ValueError as exc:
        db.session.rollback()
        flash("Alteração não publicada: " + str(exc), "error")
    return redirect(url_for(redirect_endpoint, **values))


def _require_change_confirmation() -> None:
    if request.form.get("confirm_changes") != "yes":
        raise ValueError("Revise o resumo das alterações e confirme antes de prosseguir.")


def _latest_scanned_blocks(limit: int = 6) -> list[dict]:
    """Join recent public-file checks with the block catalog for a compact summary."""
    blocks = {block.filename: block for block in NetworkBlock.query.all()}
    summary: list[dict] = []
    seen: set[str] = set()
    checks = HealthCheck.query.order_by(HealthCheck.checked_at.desc()).limit(max(limit * 5, 30)).all()
    for check in checks:
        filename = Path(urlparse(check.target).path).name
        if not filename or filename in seen:
            continue
        seen.add(filename)
        summary.append({"check": check, "block": blocks.get(filename), "filename": filename})
        if len(summary) >= limit:
            break
    return summary


def _online_users(window_minutes: int = 5) -> list[User]:
    cutoff = utcnow() - timedelta(minutes=window_minutes)
    return User.query.filter(
        User.active.is_(True), User.deleted_at.is_(None), User.last_seen_at >= cutoff
    ).order_by(User.last_seen_at.desc(), User.email).all()


def _admin_scans_token() -> str:
    secret = str(current_app.config.get("SSO_SIGNING_SECRET", ""))
    if not secret:
        return ""
    return hmac.new(
        secret.encode("utf-8"),
        b"isp-network-tools:admin-scans:v1",
        hashlib.sha256,
    ).hexdigest()


def _fetch_running_scans() -> dict:
    """Read active health scans over the private Docker network."""
    base_url = str(current_app.config.get("HEALTH_INTERNAL_BASE_URL", "")).rstrip("/")
    token = _admin_scans_token()
    if not base_url or not token:
        return {"available": False, "scans": []}
    try:
        health_host = urlparse(
            str(current_app.config.get("HEALTH_BASE_URL", ""))
        ).netloc or "network-health.localhost"
        response = requests.get(
            f"{base_url}/internal/admin/scans",
            # Flask's trusted-host check sees the Docker service name as Host;
            # use the configured public health hostname for the internal call.
            headers={"X-ISP-Admin-Token": token, "Host": health_host},
            timeout=3,
        )
        response.raise_for_status()
        payload = response.json()
    except (requests.RequestException, ValueError):
        current_app.logger.warning("Consulta de scans ativos indisponível")
        return {"available": False, "scans": []}
    scans = payload.get("scans", []) if isinstance(payload, dict) else []
    return {
        "available": True,
        "scans": [scan for scan in scans if isinstance(scan, dict)],
    }


def _dashboard_map_data(snapshot: dict) -> dict:
    """Aggregate geofeed prefixes as blocks at macroregion/state/city levels."""
    macro_names = {
        "AC": "Norte", "AP": "Norte", "AM": "Norte", "PA": "Norte", "RO": "Norte", "RR": "Norte", "TO": "Norte",
        "AL": "Nordeste", "BA": "Nordeste", "CE": "Nordeste", "MA": "Nordeste", "PB": "Nordeste", "PE": "Nordeste", "PI": "Nordeste", "RN": "Nordeste", "SE": "Nordeste",
        "DF": "Centro-Oeste", "GO": "Centro-Oeste", "MT": "Centro-Oeste", "MS": "Centro-Oeste",
        "ES": "Sudeste", "MG": "Sudeste", "RJ": "Sudeste", "SP": "Sudeste",
        "PR": "Sul", "RS": "Sul", "SC": "Sul",
    }
    macro: dict[str, dict] = {}
    states: dict[str, dict] = {}
    cities: dict[tuple[str, str], dict] = {}

    def new_bucket(**extra):
        return {"blocks": 0, "ipv4": 0, "ipv6": 0, "companies": {}, **extra}

    def add_block(bucket: dict, company_name: str, family: str) -> None:
        bucket["blocks"] += 1
        bucket[family] += 1
        company = bucket["companies"].setdefault(
            company_name,
            {"name": company_name, "blocks": 0, "ipv4": 0, "ipv6": 0},
        )
        company["blocks"] += 1
        company[family] += 1

    for block in snapshot.get("blocks", []):
        if not block.get("active"):
            continue
        company_name = str(block.get("company_name") or "Empresa não informada").strip()
        for entry in block.get("entries", []):
            region = str(entry.get("region") or "").upper()
            uf = region.split("-", 1)[1] if region.startswith("BR-") else ""
            if len(uf) != 2:
                continue
            try:
                network = ipaddress.ip_network(entry["prefix"], strict=True)
            except (KeyError, ValueError):
                continue
            # Each valid geofeed prefix is one block on the map.  Do not use
            # num_addresses here: IPv6 address totals are not the requested
            # metric and cannot be represented safely by browser numbers.
            family = "ipv4" if network.version == 4 else "ipv6"
            state = states.setdefault(uf, new_bucket())
            add_block(state, company_name, family)
            macro_name = macro_names.get(uf, "Outros")
            macroregion = macro.setdefault(macro_name, new_bucket())
            add_block(macroregion, company_name, family)
            city_name = str(entry.get("city") or "").strip()
            if city_name:
                city = cities.setdefault((uf, city_name.casefold()), new_bucket(region=uf, city=city_name))
                add_block(city, company_name, family)

    def serialize(items):
        output = []
        for key, item in sorted(items.items()):
            output.append(
                {
                    "region": key,
                    **{field: str(item[field]) for field in ("blocks", "ipv4", "ipv6")},
                    "companies": [
                        {
                            "name": company["name"],
                            **{field: str(company[field]) for field in ("blocks", "ipv4", "ipv6")},
                        }
                        for company in sorted(item["companies"].values(), key=lambda value: value["name"].casefold())
                    ],
                    **({"city": item["city"]} if "city" in item else {}),
                }
            )
        return output

    city_items = []
    for item in sorted(cities.values(), key=lambda value: (str(value["region"]), str(value["city"]))):
        city_items.append({
            "region": item["region"], "city": item["city"],
            **{field: str(item[field]) for field in ("blocks", "ipv4", "ipv6")},
            "companies": [
                {
                    "name": company["name"],
                    **{field: str(company[field]) for field in ("blocks", "ipv4", "ipv6")},
                }
                for company in sorted(item["companies"].values(), key=lambda value: value["name"].casefold())
            ],
        })
    return {"macroregions": serialize(macro), "states": serialize(states), "cities": city_items}


def _create_change_request(
    snapshot: dict,
    title: str,
    notes: str,
    requester: User,
    *,
    allow_invalid: bool = False,
) -> ChangeRequest:
    validation = validate_snapshot(snapshot)
    if not validation.valid and not allow_invalid:
        raise ValueError(validation.errors[0])
    old = latest_published_snapshot()
    diff = diff_snapshots(old, snapshot)
    if not diff:
        raise ValueError("Não há alterações em relação à versão publicada.")
    change = ChangeRequest(
        title=_clean(title, 180),
        notes=_clean(notes, 4000),
        status="pending",
        snapshot_json=canonical_json(snapshot),
        snapshot_hash=snapshot_hash(snapshot),
        diff_text=diff,
        requested_by_id=requester.id,
    )
    db.session.add(change)
    db.session.flush()
    audit("change.submitted", "change", change.id, {"title": change.title}, user=requester)
    admins = User.query.filter(User.role.in_(["super_admin", "admin"]), User.active.is_(True)).order_by(User.email).all()
    create_in_app_notifications(
        admins,
        f"Aprovação pendente #{change.id}",
        f"{requester.email} enviou: {change.title}",
        url_for("panel.change_detail", change_id=change.id),
    )
    send_notification(
        [user.email for user in admins],
        f"[Geofeed] Aprovação pendente #{change.id}",
        f"{requester.email} enviou: {change.title}\n\nAcesse o painel administrativo para revisar.",
    )
    return change


def _propose_editor_mutation(
    title: str,
    notes: str,
    mutation,
    *,
    allow_invalid: bool = False,
) -> ChangeRequest:
    """Build a proposal from a temporary editor mutation without changing working data."""
    if not notes:
        raise ValueError("Informe uma observação para o administrador.")
    mutation()
    db.session.flush()
    snapshot = build_snapshot()
    db.session.rollback()
    return _create_change_request(
        snapshot, title, notes, current_user(), allow_invalid=allow_invalid
    )


@bp.get("/")
@login_required
def dashboard():
    user = current_user()
    working = build_snapshot()
    validation = validate_snapshot(working)
    latest = Publication.query.order_by(Publication.version.desc()).first()
    running_scan_data = _fetch_running_scans() if user.is_super_admin() else {"available": True, "scans": []}
    return render_template(
        "dashboard.html",
        company_count=Company.query.filter_by(active=True).count(),
        block_count=NetworkBlock.query.filter_by(active=True).count(),
        entry_count=FeedEntry.query.count(),
        working_hash=snapshot_hash(working),
        latest=latest,
        validation=validation,
        online_user_count=User.query.filter(
            User.active.is_(True), User.deleted_at.is_(None),
            User.last_seen_at >= utcnow() - timedelta(minutes=5)
        ).count(),
        running_scan_count=len(running_scan_data["scans"]),
        map_data=_dashboard_map_data(working),
        scanned_blocks=_latest_scanned_blocks(),
    )


@bp.get("/users/online")
@roles_required("admin")
def online_users():
    return render_template("online_users.html", users=_online_users())


@bp.get("/scans/running")
@roles_required("super_admin")
def running_scans():
    scan_data = _fetch_running_scans()
    return render_template(
        "running_scans.html",
        scans=scan_data["scans"],
        scans_available=scan_data["available"],
        refreshed_at=utcnow(),
    )


@bp.get("/companies")
@login_required
def companies():
    search = _clean(request.args.get("q"), 120)
    query = Company.query
    if search:
        query = query.filter(Company.name.ilike(f"%{search}%"))
    return render_template(
        "companies.html", companies=query.order_by(Company.name).all(), search=search
    )


@bp.route("/companies/new", methods=["GET", "POST"])
@roles_required("admin")
def company_new():
    if request.method == "POST":
        try:
            company = Company(
                name=_clean(request.form.get("name"), 120),
                default_asn=_integer(request.form.get("default_asn"), "ASN"),
                contact_email=_email(request.form.get("contact_email", ""), required=False),
                active=True,
            )
            if not company.name:
                raise ValueError("O nome é obrigatório.")
            db.session.add(company)
            db.session.flush()
            audit("company.created", "company", company.id, {"name": company.name})
            return _commit_or_flash("Empresa cadastrada.", "panel.companies")
        except ValueError as exc:
            db.session.rollback()
            flash(str(exc), "error")
    return render_template("company_form.html", company=None)


@bp.route("/companies/<int:company_id>/edit", methods=["GET", "POST"])
@roles_required("admin")
def company_edit(company_id: int):
    company = db.get_or_404(Company, company_id)
    if request.method == "POST":
        try:
            before = {"name": company.name, "asn": company.default_asn}
            company.name = _clean(request.form.get("name"), 120)
            company.default_asn = _integer(request.form.get("default_asn"), "ASN")
            company.contact_email = _email(
                request.form.get("contact_email", ""), required=False
            )
            company.active = request.form.get("active") == "on"
            if not company.name:
                raise ValueError("O nome é obrigatório.")
            audit(
                "company.updated",
                "company",
                company.id,
                {"before": before, "after": {"name": company.name, "asn": company.default_asn}},
            )
            return _commit_or_flash("Empresa atualizada.", "panel.companies")
        except ValueError as exc:
            db.session.rollback()
            flash(str(exc), "error")
    return render_template("company_form.html", company=company)


@bp.route("/companies/<int:company_id>/delete", methods=["GET", "POST"])
@roles_required("admin")
def company_delete(company_id: int):
    company = db.get_or_404(Company, company_id)
    blocks = list(company.blocks)
    entries = sum(len(block.entries) for block in blocks)
    consequences = [
        f"Empresa {company.name}",
        f"{len(blocks)} bloco(s) IP: " + (", ".join(block.cidr for block in blocks) or "nenhum"),
        f"{entries} entrada(s) de geolocalização em todos os blocos",
        "Os arquivos públicos serão atualizados na próxima publicação.",
        "Publicações históricas e registros de auditoria serão preservados.",
    ]
    if request.method == "POST":
        if request.form.get("confirm") != "yes":
            abort(400)
        audit(
            "company.deleted",
            "company",
            company.id,
            {"name": company.name, "blocks": [block.cidr for block in blocks], "entries": entries},
            user=current_user(),
        )
        db.session.delete(company)
        return _commit_or_flash("Empresa e dados associados excluídos.", "panel.companies")
    return render_template(
        "delete_confirm.html",
        title="Excluir empresa",
        heading=f"Excluir {company.name}?",
        message="Esta ação permanente removerá os dados ativos associados à empresa.",
        consequences=consequences,
        cancel_endpoint="panel.companies",
        cancel_values={},
    )


@bp.get("/blocks")
@login_required
def blocks():
    search = _clean(request.args.get("q"), 120)
    family = request.args.get("family", "all")
    query = NetworkBlock.query.join(Company)
    if search:
        query = query.filter(
            or_(
                NetworkBlock.cidr.ilike(f"%{search}%"),
                NetworkBlock.filename.ilike(f"%{search}%"),
                Company.name.ilike(f"%{search}%"),
            )
        )
    if family in {"4", "6"}:
        query = query.filter(NetworkBlock.ip_version == int(family))
    block_list = query.order_by(NetworkBlock.ip_version, NetworkBlock.cidr).all()
    block_reviews = {block.id: _block_review(block) for block in block_list}
    return render_template(
        "blocks.html",
        blocks=block_list,
        companies=Company.query.filter_by(active=True).order_by(Company.name).all(),
        search=search,
        family=family,
        block_reviews=block_reviews,
    )


@bp.get("/blocks/review")
@roles_required("admin", "editor")
def block_review():
    reviewed = [(block, _block_review(block)) for block in NetworkBlock.query.join(Company).order_by(NetworkBlock.cidr).all()]
    return render_template("block_review.html", reviewed=[item for item in reviewed if item[1]])


@bp.post("/blocks/bulk-update")
@roles_required("admin", "editor")
def blocks_bulk_update():
    try:
        block_ids = {int(value) for value in request.form.getlist("block_ids")}
    except ValueError:
        block_ids = set()
    blocks_list = NetworkBlock.query.filter(NetworkBlock.id.in_(block_ids)).all() if block_ids else []
    if not blocks_list:
        flash("Selecione ao menos um bloco.", "error")
        return redirect(url_for("panel.blocks"))
    fields = request.form.getlist("fields")
    if not fields:
        fields = [
            field for field, value in (
                ("company", request.form.get("company_id")),
                ("asn", request.form.get("asn")),
                ("description", request.form.get("description")),
                ("active", request.form.get("active")),
            ) if value not in (None, "")
        ]
    if not fields:
        flash("Selecione ao menos uma informação para atualizar.", "error")
        return redirect(url_for("panel.blocks"))
    notes = _clean(request.form.get("notes"), 4000)
    company = None
    if "company" in fields:
        company = db.session.get(Company, _integer(request.form.get("company_id"), "Empresa"))
        if not company or not company.active:
            flash("Empresa inválida.", "error")
            return redirect(url_for("panel.blocks"))
    asn = _integer(request.form.get("asn"), "ASN") if "asn" in fields else None
    description = _clean(request.form.get("description"), 255) if "description" in fields else None
    active = request.form.get("active") == "on" if "active" in fields else None

    def mutation():
        for block in blocks_list:
            if company:
                block.company_id = company.id
            if asn is not None:
                block.asn = asn
            if description is not None:
                block.description = description
            if active is not None:
                block.active = active

    try:
        _require_change_confirmation()
        if current_user().role == "editor":
            change = _propose_editor_mutation(
                f"Atualização em massa de {len(blocks_list)} bloco(s)", notes, mutation
            )
            db.session.commit()
            flash("Atualização enviada para aprovação do administrador.", "success")
            return redirect(url_for("panel.change_detail", change_id=change.id))
        before = {block.id: {"company_id": block.company_id, "asn": block.asn, "active": block.active} for block in blocks_list}
        mutation()
        for block in blocks_list:
            audit("block.bulk_updated", "block", block.id, {"before": before[block.id]}, user=current_user())
        return _publish_or_flash(
            f"Atualização de {len(blocks_list)} bloco(s).", "panel.blocks"
        )
    except ValueError as exc:
        db.session.rollback()
        flash(str(exc), "error")
        return redirect(url_for("panel.blocks"))


@bp.post("/entries/bulk-update")
@roles_required("admin", "editor")
def entries_bulk_update():
    try:
        entry_ids = {int(value) for value in request.form.getlist("entry_ids")}
    except ValueError:
        entry_ids = set()
    entries = FeedEntry.query.filter(FeedEntry.id.in_(entry_ids)).all() if entry_ids else []
    if not entries:
        flash("Selecione ao menos uma entrada.", "error")
        return redirect(request.referrer or url_for("panel.blocks"))
    fields = request.form.getlist("fields")
    if not fields:
        flash("Selecione ao menos uma informação para atualizar.", "error")
        return redirect(request.referrer or url_for("panel.blocks"))
    values = {
        "alpha2code": _clean(request.form.get("alpha2code"), 2).upper(),
        "region": _clean(request.form.get("region"), 16).upper(),
        "city": _clean(request.form.get("city"), 160),
        "postal_code": _clean(request.form.get("postal_code"), 32),
    }
    notes = _clean(request.form.get("notes"), 4000)

    def mutation():
        for entry in entries:
            for field in fields:
                setattr(entry, field, values[field])

    try:
        _require_change_confirmation()
        if current_user().role == "editor":
            change = _propose_editor_mutation(
                f"Atualização em massa de {len(entries)} entrada(s)", notes, mutation
            )
            db.session.commit()
            flash("Atualização enviada para aprovação do administrador.", "success")
            return redirect(url_for("panel.change_detail", change_id=change.id))
        mutation()
        for entry in entries:
            audit("entry.bulk_updated", "entry", entry.id, {"fields": fields}, user=current_user())
        validation = validate_snapshot(build_snapshot())
        if validation.errors:
            raise ValueError(validation.errors[0])
        return _publish_or_flash(
            f"Atualização de {len(entries)} entrada(s).",
            "panel.block_detail",
            block_id=entries[0].block_id,
        )
    except ValueError as exc:
        db.session.rollback()
        flash(str(exc), "error")
        return redirect(request.referrer or url_for("panel.blocks"))


@bp.route("/blocks/new", methods=["GET", "POST"])
@roles_required("admin", "editor")
def block_new():
    companies_list = Company.query.filter_by(active=True).order_by(Company.name).all()
    if request.method == "POST":
        try:
            network, _suggestion = _network_input(request.form.get("cidr"), request.form)
            company_id = _integer(request.form.get("company_id"), "Empresa")
            company = db.session.get(Company, company_id)
            if not company or not company.active:
                raise ValueError("Empresa inválida.")
            asn = _integer(request.form.get("asn"), "ASN")
            filename = _clean(request.form.get("filename"), 128).lower()
            description = _clean(request.form.get("description"), 255)
            if current_user().role == "editor":
                notes = _clean(request.form.get("notes"), 4000)

                def mutation():
                    db.session.add(
                        NetworkBlock(
                            cidr=str(network),
                            ip_version=network.version,
                            company_id=company.id,
                            asn=asn,
                            filename=filename,
                            description=description,
                            active=True,
                        )
                    )

                change = _propose_editor_mutation(
                    f"Novo bloco {network}", notes, mutation, allow_invalid=True
                )
                db.session.commit()
                flash("Cadastro enviado para aprovação do administrador.", "success")
                return redirect(url_for("panel.change_detail", change_id=change.id))

            block = NetworkBlock(
                cidr=str(network),
                ip_version=network.version,
                company_id=company.id,
                asn=asn,
                filename=filename,
                description=description,
                active=True,
            )
            db.session.add(block)
            db.session.flush()
            audit("block.created", "block", block.id, {"cidr": block.cidr})
            return _commit_or_flash(
                "Bloco cadastrado. Agora adicione ou importe as entradas.",
                "panel.block_detail",
                block_id=block.id,
            )
        except SubnetSuggestion as exc:
            db.session.rollback()
            return render_template(
                "block_form.html", block=None, companies=companies_list, suggested_cidr=exc.suggested
            )
        except ValueError as exc:
            db.session.rollback()
            flash(str(exc), "error")
    return render_template("block_form.html", block=None, companies=companies_list)


@bp.route("/blocks/<int:block_id>/edit", methods=["GET", "POST"])
@roles_required("admin", "editor")
def block_edit(block_id: int):
    block = db.get_or_404(NetworkBlock, block_id)
    companies_list = Company.query.order_by(Company.name).all()
    if request.method == "POST":
        try:
            _require_change_confirmation()
            network, _suggestion = _network_input(request.form.get("cidr"), request.form)
            company = db.session.get(
                Company, _integer(request.form.get("company_id"), "Empresa")
            )
            if not company:
                raise ValueError("Empresa inválida.")
            before = {"cidr": block.cidr, "asn": block.asn, "filename": block.filename}
            asn = _integer(request.form.get("asn"), "ASN")
            filename = _clean(request.form.get("filename"), 128).lower()
            description = _clean(request.form.get("description"), 255)
            active = request.form.get("active") == "on"
            if current_user().role == "editor":
                notes = _clean(request.form.get("notes"), 4000)

                def mutation():
                    block.cidr = str(network)
                    block.ip_version = network.version
                    block.company_id = company.id
                    block.asn = asn
                    block.filename = filename
                    block.description = description
                    block.active = active

                change = _propose_editor_mutation(
                    f"Alteração do bloco {block.cidr}", notes, mutation
                )
                db.session.commit()
                flash("Alteração enviada para aprovação do administrador.", "success")
                return redirect(url_for("panel.change_detail", change_id=change.id))

            block.cidr = str(network)
            block.ip_version = network.version
            block.company_id = company.id
            block.asn = asn
            block.filename = filename
            block.description = description
            block.active = active
            audit(
                "block.updated",
                "block",
                block.id,
                {"before": before, "after": {"cidr": block.cidr, "asn": block.asn, "filename": block.filename}},
            )
            return _publish_or_flash(
                f"Bloco {block.cidr} atualizado.",
                "panel.block_detail",
                block_id=block.id,
            )
        except SubnetSuggestion as exc:
            db.session.rollback()
            return render_template(
                "block_form.html", block=block, companies=companies_list, suggested_cidr=exc.suggested
            )
        except ValueError as exc:
            db.session.rollback()
            flash(str(exc), "error")
    return render_template("block_form.html", block=block, companies=companies_list)


@bp.route("/blocks/<int:block_id>/delete", methods=["GET", "POST"])
@roles_required("admin")
def block_delete(block_id: int):
    block = db.get_or_404(NetworkBlock, block_id)
    entries = list(block.entries)
    consequences = [
        f"Bloco {block.cidr}",
        f"Arquivo gerado {block.filename}",
        f"{len(entries)} entrada(s) de geolocalização",
        "O arquivo público será removido na próxima publicação.",
        "Publicações históricas e registros de auditoria serão preservados.",
    ]
    if request.method == "POST":
        if request.form.get("confirm") != "yes":
            abort(400)
        audit(
            "block.deleted",
            "block",
            block.id,
            {"cidr": block.cidr, "filename": block.filename, "entries": len(entries)},
            user=current_user(),
        )
        db.session.delete(block)
        return _commit_or_flash("Bloco e entradas associados excluídos.", "panel.blocks")
    return render_template(
        "delete_confirm.html",
        title="Excluir bloco",
        heading=f"Excluir {block.cidr}?",
        message="Esta ação permanente removerá o bloco e todas as suas entradas ativas.",
        consequences=consequences,
        cancel_endpoint="panel.block_detail",
        cancel_values={"block_id": block.id},
    )


@bp.get("/blocks/<int:block_id>")
@login_required
def block_detail(block_id: int):
    block = db.get_or_404(NetworkBlock, block_id)
    return render_template("block_detail.html", block=block)


@bp.get("/blocks/<int:block_id>/preview.csv")
@login_required
def block_preview_csv(block_id: int):
    block = db.get_or_404(NetworkBlock, block_id)
    snapshot = build_snapshot()
    block_data = next(item for item in snapshot["blocks"] if item["id"] == block.id)
    validation = validate_snapshot({"schema": 1, "companies": snapshot["companies"], "blocks": [block_data]})
    if not validation.valid:
        flash("A prévia não pode ser gerada enquanto o bloco tiver erros.", "error")
        return redirect(url_for("panel.block_detail", block_id=block.id))
    return send_file(
        io.BytesIO(generate_csv(block_data)),
        mimetype="text/csv; charset=utf-8",
        as_attachment=True,
        download_name=block.filename,
        max_age=0,
    )


@bp.get("/working/geofeeds.zip")
@login_required
def working_zip():
    snapshot = build_snapshot()
    validation = validate_snapshot(snapshot)
    if not validation.valid:
        flash("O ZIP não pode ser gerado enquanto houver erros de validação.", "error")
        return redirect(url_for("panel.dashboard"))
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", zipfile.ZIP_DEFLATED) as bundle:
        for item in snapshot["blocks"]:
            if item.get("active"):
                bundle.writestr(item["filename"], generate_csv(item))
    output.seek(0)
    return send_file(
        output,
        mimetype="application/zip",
        as_attachment=True,
        download_name="geofeeds-rascunho.zip",
        max_age=0,
    )


@bp.post("/blocks/<int:block_id>/toggle")
@roles_required("admin", "editor")
def block_toggle(block_id: int):
    block = db.get_or_404(NetworkBlock, block_id)
    if current_user().role == "editor":
        notes = _clean(request.form.get("notes"), 4000)

        def mutation():
            block.active = not block.active

        try:
            change = _propose_editor_mutation(
                f"Alteração de status do bloco {block.cidr}", notes, mutation
            )
            db.session.commit()
            flash("Alteração enviada para aprovação do administrador.", "success")
            return redirect(url_for("panel.change_detail", change_id=change.id))
        except ValueError as exc:
            db.session.rollback()
            flash(str(exc), "error")
            return redirect(url_for("panel.block_detail", block_id=block.id))

    block.active = not block.active
    audit("block.toggled", "block", block.id, {"active": block.active})
    return _commit_or_flash("Status do bloco atualizado.", "panel.blocks")


@bp.route("/blocks/<int:block_id>/entries/new", methods=["GET", "POST"])
@roles_required("admin", "editor")
def entry_new(block_id: int):
    block = db.get_or_404(NetworkBlock, block_id)
    if request.method == "POST":
        try:
            if current_user().role == "editor":
                notes = _clean(request.form.get("notes"), 4000)

                def mutation():
                    entry = FeedEntry(block_id=block.id)
                    _fill_entry(entry, request.form)
                    db.session.add(entry)

                change = _propose_editor_mutation(
                    f"Nova entrada no bloco {block.cidr}", notes, mutation
                )
                db.session.commit()
                flash("Entrada enviada para aprovação do administrador.", "success")
                return redirect(url_for("panel.change_detail", change_id=change.id))

            entry = FeedEntry(block_id=block.id)
            _fill_entry(entry, request.form)
            db.session.add(entry)
            db.session.flush()
            validation = validate_snapshot(build_snapshot())
            if validation.errors:
                raise ValueError(validation.errors[0])
            audit("entry.created", "entry", entry.id, {"prefix": entry.prefix})
            return _commit_or_flash(
                "Entrada cadastrada.", "panel.block_detail", block_id=block.id
            )
        except SubnetSuggestion as exc:
            db.session.rollback()
            return render_template(
                "entry_form.html", block=block, entry=None, suggested_cidr=exc.suggested
            )
        except ValueError as exc:
            db.session.rollback()
            flash(str(exc), "error")
    return render_template("entry_form.html", block=block, entry=None)


def _fill_entry(entry: FeedEntry, form) -> None:
    prefix, _suggestion = _network_input(form.get("prefix"), form)
    entry.prefix = str(prefix)
    entry.alpha2code = _clean(form.get("alpha2code"), 2).upper()
    entry.region = _clean(form.get("region"), 16).upper()
    entry.city = _clean(form.get("city"), 160)
    entry.postal_code = _clean(form.get("postal_code"), 32)
    entry.sort_order = _integer(form.get("sort_order", "0"), "Ordem", minimum=0)


@bp.route("/entries/<int:entry_id>/edit", methods=["GET", "POST"])
@roles_required("admin", "editor")
def entry_edit(entry_id: int):
    entry = db.get_or_404(FeedEntry, entry_id)
    block = entry.block
    if request.method == "POST":
        try:
            _require_change_confirmation()
            before = entry.prefix
            if current_user().role == "editor":
                notes = _clean(request.form.get("notes"), 4000)

                def mutation():
                    _fill_entry(entry, request.form)

                change = _propose_editor_mutation(
                    f"Alteração de entrada no bloco {block.cidr}", notes, mutation
                )
                db.session.commit()
                flash("Alteração enviada para aprovação do administrador.", "success")
                return redirect(url_for("panel.change_detail", change_id=change.id))

            _fill_entry(entry, request.form)
            db.session.flush()
            validation = validate_snapshot(build_snapshot())
            if validation.errors:
                raise ValueError(validation.errors[0])
            audit("entry.updated", "entry", entry.id, {"before": before, "after": entry.prefix})
            return _publish_or_flash(
                f"Entrada {entry.prefix} atualizada.",
                "panel.block_detail",
                block_id=block.id,
            )
        except SubnetSuggestion as exc:
            db.session.rollback()
            return render_template(
                "entry_form.html", block=block, entry=entry, suggested_cidr=exc.suggested
            )
        except ValueError as exc:
            db.session.rollback()
            flash(str(exc), "error")
    return render_template("entry_form.html", block=block, entry=entry)


@bp.post("/entries/<int:entry_id>/delete")
@roles_required("admin", "editor")
def entry_delete(entry_id: int):
    entry = db.get_or_404(FeedEntry, entry_id)
    block_id, prefix = entry.block_id, entry.prefix
    if current_user().role == "editor":
        notes = _clean(request.form.get("notes"), 4000)

        def mutation():
            db.session.delete(entry)

        try:
            change = _propose_editor_mutation(
                f"Remoção de entrada do bloco {entry.block.cidr}", notes, mutation
            )
            db.session.commit()
            flash("Remoção enviada para aprovação do administrador.", "success")
            return redirect(url_for("panel.change_detail", change_id=change.id))
        except ValueError as exc:
            db.session.rollback()
            flash(str(exc), "error")
            return redirect(url_for("panel.block_detail", block_id=block_id))

    db.session.delete(entry)
    audit("entry.deleted", "entry", entry_id, {"prefix": prefix})
    return _commit_or_flash(
        "Entrada removida do rascunho.", "panel.block_detail", block_id=block_id
    )


@bp.post("/blocks/<int:block_id>/rdap-check")
@roles_required("admin", "editor")
@limiter.limit("30 per hour")
def block_rdap(block_id: int):
    block = db.get_or_404(NetworkBlock, block_id)
    try:
        result = rdap_check(block)
        audit("block.rdap_checked", "block", block.id, result)
        db.session.commit()
        if result["ok"]:
            flash(f"RDAP confirmado: {result['handle']} vinculado ao AS{result['rdap_asn']}.", "success")
        else:
            flash("A consulta RDAP apresentou divergência. Revise o bloco e o ASN.", "warning")
    except Exception as exc:
        current_app.logger.warning("Consulta RDAP falhou: %s", type(exc).__name__)
        flash("Não foi possível consultar o RDAP neste momento.", "error")
    return redirect(url_for("panel.block_detail", block_id=block.id))


@bp.get("/users")
@roles_required("admin")
def users():
    return render_template(
        "users.html",
        users=User.query.filter(User.deleted_at.is_(None)).order_by(User.email).all(),
        role_names=_role_names(),
    )


@bp.get("/access")
@roles_required("super_admin")
def access():
    role_list = _roles_for_form()
    role_permissions = {}
    for role in role_list:
        try:
            role_permissions[role.code] = json.loads(role.permissions or "[]")
        except json.JSONDecodeError:
            role_permissions[role.code] = []
    return render_template("access.html", roles=role_list, role_permissions=role_permissions,
        sectors=Sector.query.order_by(Sector.active.desc(), Sector.name).all(), permission_options=PERMISSION_OPTIONS)


@bp.get("/access/applications")
@roles_required("super_admin")
def application_access():
    applications = Application.query.filter_by(active=True).order_by(Application.sort_order, Application.name).all()
    return render_template(
        "application_access.html",
        applications=applications,
        groups=Group.query.filter_by(active=True).order_by(Group.name).all(),
        users=User.query.filter(User.deleted_at.is_(None), User.active.is_(True)).order_by(User.email).all(),
    )


@bp.get("/sso/issue")
@login_required
@limiter.limit("30 per hour")
def issue_sso():
    """Issue a short-lived, one-time-consumed handoff to a protected app."""
    target = request.args.get("target", "")
    user = current_user()
    if target != "isp_network_health" or not user.has_application_access(target):
        abort(403)
    secret = current_app.config.get("SSO_SIGNING_SECRET", "")
    if not secret:
        abort(503)
    token = issue_handoff(
        secret,
        subject=str(user.id),
        email=user.email,
        display_name=user.display_name or user.email,
        role=user.role,
        applications=[target],
        audience=target,
    )
    callback = f"{current_app.config['HEALTH_BASE_URL'].rstrip('/')}/sso/callback"
    return redirect(f"{callback}?{urlencode({'token': token})}")


@bp.post("/access/groups")
@roles_required("super_admin")
def group_create():
    name = _clean(request.form.get("name"), 120)
    description = _clean(request.form.get("description"), 255)
    if not name:
        flash("Informe o nome do grupo.", "error")
        return redirect(url_for("panel.application_access"))
    if Group.query.filter(func.lower(Group.name) == name.casefold()).first():
        flash("Este grupo já está cadastrado.", "error")
        return redirect(url_for("panel.application_access"))
    group = Group(name=name, description=description, active=True)
    db.session.add(group)
    db.session.flush()
    audit("group.created", "group", group.id, {"name": name}, user=current_user())
    return _commit_or_flash("Grupo criado.", "panel.application_access")


@bp.post("/access/groups/<int:group_id>/members")
@roles_required("super_admin")
def group_members_update(group_id: int):
    group = db.get_or_404(Group, group_id)
    user_ids = set()
    for value in request.form.getlist("user_ids"):
        try:
            user_ids.add(int(value))
        except ValueError:
            continue
    group.users = User.query.filter(User.id.in_(user_ids), User.active.is_(True), User.deleted_at.is_(None)).all() if user_ids else []
    audit("group.members_updated", "group", group.id, {"user_ids": sorted(user_ids)}, user=current_user())
    return _commit_or_flash("Membros do grupo atualizados.", "panel.application_access")


@bp.post("/access/applications/users/<int:user_id>")
@roles_required("super_admin")
def user_application_access_update(user_id: int):
    user = db.get_or_404(User, user_id)
    applications = Application.query.filter_by(active=True, public=False).all()
    for application in applications:
        value = request.form.get(f"application_{application.code}", "inherit")
        grant = UserApplicationGrant.query.filter_by(user_id=user.id, application_id=application.id).first()
        if value == "inherit":
            if grant:
                db.session.delete(grant)
        elif value in {"allow", "deny"}:
            if not grant:
                grant = UserApplicationGrant(user_id=user.id, application_id=application.id)
                db.session.add(grant)
            grant.allowed = value == "allow"
    audit("user.application_access_updated", "user", user.id, {"applications": request.form.to_dict()}, user=current_user())
    return _commit_or_flash("Acesso individual às aplicações atualizado.", "panel.application_access")


@bp.post("/access/applications/groups/<int:group_id>")
@roles_required("super_admin")
def group_application_access_update(group_id: int):
    group = db.get_or_404(Group, group_id)
    selected = set(request.form.getlist("application_codes"))
    applications = Application.query.filter_by(active=True, public=False).all()
    for application in applications:
        grant = GroupApplicationGrant.query.filter_by(group_id=group.id, application_id=application.id).first()
        if application.code in selected and not grant:
            db.session.add(GroupApplicationGrant(group_id=group.id, application_id=application.id, allowed=True))
        elif application.code not in selected and grant:
            db.session.delete(grant)
    audit("group.application_access_updated", "group", group.id, {"applications": sorted(selected)}, user=current_user())
    return _commit_or_flash("Acesso do grupo às aplicações atualizado.", "panel.application_access")


@bp.post("/access/sectors")
@roles_required("super_admin")
def sector_create():
    name = _clean(request.form.get("name"), 120)
    if not name:
        flash("Informe o nome do setor.", "error")
        return redirect(url_for("panel.settings", section="access", tab="sectors"))
    if Sector.query.filter(func.lower(Sector.name) == name.casefold()).first():
        flash("Este setor já está cadastrado.", "error")
        return redirect(url_for("panel.settings", section="access", tab="sectors"))
    db.session.add(Sector(name=name))
    audit("sector.created", "sector", name, {"name": name}, user=current_user())
    return _commit_or_flash("Setor cadastrado.", "panel.settings", section="access", tab="sectors")


@bp.post("/access/sectors/<int:sector_id>/toggle")
@roles_required("super_admin")
def sector_toggle(sector_id: int):
    sector = db.get_or_404(Sector, sector_id)
    sector.active = not sector.active
    audit("sector.status_changed", "sector", sector.id, {"active": sector.active}, user=current_user())
    return _commit_or_flash("Status do setor atualizado.", "panel.settings", section="access", tab="sectors")


@bp.post("/access/sectors/<int:sector_id>/update")
@roles_required("super_admin")
def sector_update(sector_id: int):
    sector = db.get_or_404(Sector, sector_id)
    name = _clean(request.form.get("name"), 120)
    if not name:
        flash("Informe o nome do setor.", "error")
        return redirect(url_for("panel.settings", section="access", tab="sectors"))
    duplicate = Sector.query.filter(func.lower(Sector.name) == name.casefold(), Sector.id != sector.id).first()
    if duplicate:
        flash("Este setor já está cadastrado.", "error")
        return redirect(url_for("panel.settings", section="access", tab="sectors"))
    old_name = sector.name
    sector.name = name
    sector.active = request.form.get("active") == "on"
    User.query.filter(func.lower(User.department) == old_name.casefold()).update(
        {User.department: name}, synchronize_session=False
    )
    audit("sector.updated", "sector", sector.id, {"before": old_name, "after": name, "active": sector.active})
    return _commit_or_flash("Setor atualizado.", "panel.settings", section="access", tab="sectors")


@bp.post("/access/sectors/<int:sector_id>/delete")
@roles_required("super_admin")
def sector_delete(sector_id: int):
    sector = db.get_or_404(Sector, sector_id)
    dependents = User.query.filter(
        User.deleted_at.is_(None), func.lower(User.department) == sector.name.casefold()
    ).order_by(User.email).all()
    if dependents:
        names = ", ".join(user.display_name or user.email for user in dependents[:8])
        suffix = "…" if len(dependents) > 8 else ""
        flash(f"Não é possível excluir: setor usado por {names}{suffix}.", "error")
        return redirect(url_for("panel.settings", section="access", tab="sectors"))
    audit("sector.deleted", "sector", sector.id, {"name": sector.name})
    db.session.delete(sector)
    return _commit_or_flash("Setor excluído.", "panel.settings", section="access", tab="sectors")


@bp.post("/access/functions")
@roles_required("super_admin")
def function_create():
    name = _clean(request.form.get("name"), 120)
    if not name:
        flash("Informe o nome da função.", "error")
        return redirect(url_for("panel.settings", section="access", tab="functions"))
    if JobFunction.query.filter(func.lower(JobFunction.name) == name.casefold()).first():
        flash("Esta função já está cadastrada.", "error")
        return redirect(url_for("panel.settings", section="access", tab="functions"))
    db.session.add(JobFunction(name=name))
    audit("function.created", "job_function", name, {"name": name}, user=current_user())
    return _commit_or_flash("Função cadastrada.", "panel.settings", section="access", tab="functions")


@bp.post("/access/functions/<int:function_id>/toggle")
@roles_required("super_admin")
def function_toggle(function_id: int):
    function = db.get_or_404(JobFunction, function_id)
    function.active = not function.active
    audit("function.status_changed", "job_function", function.id, {"active": function.active}, user=current_user())
    return _commit_or_flash("Status da função atualizado.", "panel.settings", section="access", tab="functions")


@bp.post("/access/functions/<int:function_id>/update")
@roles_required("super_admin")
def function_update(function_id: int):
    function = db.get_or_404(JobFunction, function_id)
    name = _clean(request.form.get("name"), 120)
    if not name:
        flash("Informe o nome da função.", "error")
        return redirect(url_for("panel.settings", section="access", tab="functions"))
    duplicate = JobFunction.query.filter(
        func.lower(JobFunction.name) == name.casefold(), JobFunction.id != function.id
    ).first()
    if duplicate:
        flash("Esta função já está cadastrada.", "error")
        return redirect(url_for("panel.settings", section="access", tab="functions"))
    old_name = function.name
    function.name = name
    function.active = request.form.get("active") == "on"
    User.query.filter(func.lower(User.job_title) == old_name.casefold()).update(
        {User.job_title: name}, synchronize_session=False
    )
    audit("function.updated", "job_function", function.id, {"before": old_name, "after": name, "active": function.active})
    return _commit_or_flash("Função atualizada.", "panel.settings", section="access", tab="functions")


@bp.post("/access/functions/<int:function_id>/delete")
@roles_required("super_admin")
def function_delete(function_id: int):
    function = db.get_or_404(JobFunction, function_id)
    dependents = User.query.filter(
        User.deleted_at.is_(None), func.lower(User.job_title) == function.name.casefold()
    ).order_by(User.email).all()
    if dependents:
        names = ", ".join(user.display_name or user.email for user in dependents[:8])
        suffix = "…" if len(dependents) > 8 else ""
        flash(f"Não é possível excluir: função usada por {names}{suffix}.", "error")
        return redirect(url_for("panel.settings", section="access", tab="functions"))
    audit("function.deleted", "job_function", function.id, {"name": function.name})
    db.session.delete(function)
    return _commit_or_flash("Função excluída.", "panel.settings", section="access", tab="functions")


@bp.post("/access/roles")
@roles_required("super_admin")
def role_create():
    name = _clean(request.form.get("name"), 80)
    description = _clean(request.form.get("description"), 255)
    code = re.sub(r"[^a-z0-9]+", "_", name.casefold()).strip("_")[:56]
    if not code or code in {"super_admin", "admin", "editor"}:
        flash("Informe um nome válido para o perfil personalizado.", "error")
        return redirect(url_for("panel.settings", section="access", tab="roles"))
    if Role.query.filter_by(code=code).first():
        flash("Já existe um perfil com esse nome.", "error")
        return redirect(url_for("panel.settings", section="access", tab="roles"))
    permissions = [item for item in request.form.getlist("permissions") if item in PERMISSION_OPTIONS]
    db.session.add(Role(code=code, name=name, description=description, permissions=json.dumps(permissions, separators=(",", ":"))))
    audit("role.created", "role", code, {"name": name, "permissions": permissions}, user=current_user())
    return _commit_or_flash("Perfil personalizado criado.", "panel.settings", section="access", tab="roles")


@bp.post("/access/roles/<int:role_id>")
@roles_required("super_admin")
def role_update(role_id: int):
    role = db.get_or_404(Role, role_id)
    if role.system:
        abort(403)
    name = _clean(request.form.get("name"), 80)
    if not name:
        flash("Informe o nome do perfil.", "error")
        return redirect(url_for("panel.settings", section="access", tab="roles"))
    role.name = name
    role.description = _clean(request.form.get("description"), 255)
    role.permissions = json.dumps([item for item in request.form.getlist("permissions") if item in PERMISSION_OPTIONS], separators=(",", ":"))
    audit("role.updated", "role", role.id, {"name": role.name}, user=current_user())
    return _commit_or_flash("Perfil personalizado atualizado.", "panel.settings", section="access", tab="roles")


@bp.route("/settings", methods=["GET", "POST"])
@roles_required("super_admin")
def settings():
    section = _clean(request.form.get("settings_section") or request.args.get("section") or "auth", 24)
    if section not in {"auth", "email", "branding", "general", "access"}:
        section = "auth"
    tab = _clean(request.form.get("settings_tab") or request.args.get("tab") or "", 24)
    allowed_tabs = {
        "auth": {"m365", "google", "local"},
        "general": {"preferences", "monitoring"},
        "access": {"users", "roles", "sectors", "functions"},
    }
    if tab not in allowed_tabs.get(section, set()):
        tab = {"auth": "m365", "general": "preferences", "access": "users"}.get(section, "")

    def settings_redirect(target_section: str | None = None, target_tab: str | None = None):
        kwargs = {"section": target_section or section}
        if target_tab or tab:
            kwargs["tab"] = target_tab or tab
        return redirect(url_for("panel.settings", **kwargs))

    if request.method == "POST":
        try:
            if request.form.get("action") == "save_theme":
                theme_name = _clean(request.form.get("theme_name"), 120)
                if not theme_name:
                    raise ValueError("Informe um nome para o tema personalizado.")
                theme_config = {
                    "company_name": _clean(request.form.get("company_name"), 120),
                    "primary": _clean(request.form.get("primary_color"), 16),
                    "secondary": _clean(request.form.get("secondary_color"), 16),
                    "background_start": _clean(request.form.get("background_start"), 16),
                    "background_end": _clean(request.form.get("background_end"), 16),
                    "accent": _clean(request.form.get("accent_color"), 16),
                    "gradient": request.form.get("background_gradient") == "on",
                }
                if any(not re.fullmatch(r"#[0-9a-fA-F]{6}", theme_config[key]) for key in ("primary", "secondary", "background_start", "background_end", "accent")):
                    raise ValueError("As cores do tema devem usar o formato hexadecimal #RRGGBB.")
                db.session.add(PortalTheme(name=theme_name, config=json.dumps(theme_config, separators=(",", ":")), created_by_id=current_user().id))
                audit("theme.created", "theme", theme_name, {"name": theme_name}, user=current_user())
                db.session.commit()
                flash("Tema personalizado salvo.", "success")
                return settings_redirect("branding")
            if request.form.get("action") in {"test_email", "test_email_connection"}:
                sender_name, sender_address = _sender_from_form()
                email_config = {
                    "host": _clean(request.form.get("smtp_host"), 255),
                    "port": _clean(request.form.get("smtp_port"), 8),
                    "security": _clean(request.form.get("smtp_security"), 16),
                    "auth_method": _clean(request.form.get("smtp_auth_method"), 16),
                    "username": _clean(request.form.get("smtp_username"), 255),
                    "password": request.form.get("smtp_password") or get_setting("email.password", current_app.config.get("SMTP_PASSWORD", "")),
                    "timeout": _clean(request.form.get("smtp_timeout"), 3),
                    "from_name": sender_name,
                    "from_address": sender_address,
                    "from": format_sender(sender_name, sender_address),
                    "reply_to": _clean(request.form.get("smtp_reply_to"), 255),
                }
                connected, message = test_smtp_connection(email_config)
                if request.form.get("action") == "test_email_connection":
                    flash(message, "success" if connected else "error")
                    return settings_redirect("email")
                recipient = _email(request.form.get("test_recipient", ""))
                if not connected:
                    flash(message, "error")
                    return settings_redirect("email")
                status, details = send_test_email(recipient, email_config)
                db.session.commit()
                if status == "sent":
                    flash(f"{details} Destinatário: {recipient}.", "success")
                else:
                    flash(f"A conexão foi concluída, mas o envio falhou: {details}", "error")
                return settings_redirect("email")
            sender_name, sender_address = _sender_from_form()
            support_address = _email(request.form.get("smtp_support_address", ""), required=False)
            if not support_address:
                support_address = get_setting("email.support_address", "") or sender_address
            plain_fields = {
                "auth.m365_enabled": request.form.get("m365_enabled") == "on",
                "auth.google_enabled": request.form.get("google_enabled") == "on",
                "auth.local_enabled": request.form.get("local_enabled") == "on",
                "entra.tenant_id": _clean(request.form.get("tenant_id"), 128),
                "entra.client_id": _clean(request.form.get("client_id"), 128),
                "google.client_id": _clean(request.form.get("google_client_id"), 128),
                "email.mode": _clean(request.form.get("email_mode"), 32),
                "email.provider": _clean(request.form.get("smtp_provider") or get_setting("email.provider", "other"), 32),
                "email.host": _clean(request.form.get("smtp_host") or get_setting("email.host", current_app.config.get("SMTP_HOST", "")), 255),
                "email.port": _clean(request.form.get("smtp_port") or get_setting("email.port", str(current_app.config["SMTP_PORT"])), 8),
                "email.security": _clean(request.form.get("smtp_security") or get_setting("email.security", "starttls"), 16),
                "email.auth_method": _clean(request.form.get("smtp_auth_method") or get_setting("email.auth_method", "password"), 16),
                "email.from_name": sender_name,
                "email.from_address": sender_address,
                "email.from": format_sender(sender_name, sender_address),
                "email.reply_to": _clean(request.form.get("smtp_reply_to") or get_setting("email.reply_to", ""), 255),
                "email.support_address": support_address,
                "email.username": _clean(request.form.get("smtp_username") or get_setting("email.username", current_app.config.get("SMTP_USERNAME", "")), 255),
                "email.timeout": _clean(request.form.get("smtp_timeout") or get_setting("email.timeout", "15"), 3),
                "email.starttls": (request.form.get("smtp_security") == "starttls") if "smtp_security" in request.form else get_setting("email.security", "starttls") == "starttls",
                "branding.company_name": _clean(request.form.get("company_name"), 120),
                "branding.primary": _clean(request.form.get("primary_color"), 16),
                "branding.secondary": _clean(request.form.get("secondary_color"), 16),
                "branding.background_start": _clean(request.form.get("background_start") or get_setting("branding.background_start", "#09070d"), 16),
                "branding.background_end": _clean(request.form.get("background_end") or get_setting("branding.background_end", "#180d2c"), 16),
                "branding.gradient": request.form.get("background_gradient", "on" if get_setting("branding.gradient", "True") == "True" else "") == "on",
                "branding.accent": _clean(request.form.get("accent_color") or get_setting("branding.accent", "#b786f4"), 16),
                "general.timezone": _clean(request.form.get("timezone"), 64),
                "monitoring.after_publish_enabled": request.form.get("monitoring_after_publish_enabled") == "on",
                "monitoring.periodic_enabled": request.form.get("monitoring_periodic_enabled") == "on",
                "monitoring.periodic_interval_minutes": _clean(request.form.get("monitoring_periodic_interval_minutes") or "60", 5),
                "monitoring.timeout_seconds": _clean(request.form.get("monitoring_timeout_seconds") or "12", 3),
                "monitoring.retries": _clean(request.form.get("monitoring_retries") or "1", 2),
                "monitoring.failure_threshold": _clean(request.form.get("monitoring_failure_threshold") or "2", 2),
                "monitoring.repeat_alert_minutes": _clean(request.form.get("monitoring_repeat_alert_minutes") or "240", 5),
                "monitoring.notify_recovery": request.form.get("monitoring_notify_recovery") == "on",
                "monitoring.validate_content": request.form.get("monitoring_validate_content") == "on",
                "monitoring.recipients": "",
                "password.min_length": _clean(request.form.get("password_min_length") or "12", 3),
                "password.require_upper": request.form.get("password_require_upper") == "on",
                "password.require_lower": request.form.get("password_require_lower") == "on",
                "password.require_number": request.form.get("password_require_number") == "on",
                "password.require_symbol": request.form.get("password_require_symbol") == "on",
            }
            if plain_fields["email.mode"] not in {"smtp", "graph", "google"}:
                raise ValueError("Modo de e-mail inválido.")
            if plain_fields["email.provider"] not in {"microsoft365", "google", "amazon", "sendgrid", "mailgun", "other"}:
                raise ValueError("Provedor de e-mail inválido.")
            if plain_fields["email.security"] not in {"starttls", "ssl", "none"}:
                raise ValueError("Tipo de segurança SMTP inválido.")
            if plain_fields["email.auth_method"] not in {"password", "oauth2", "none"}:
                raise ValueError("Método de autenticação SMTP inválido.")
            try:
                if not 1 <= int(plain_fields["email.port"]) <= 65535:
                    raise ValueError
                if not 3 <= int(plain_fields["email.timeout"]) <= 60:
                    raise ValueError
            except (TypeError, ValueError):
                raise ValueError("Porta deve estar entre 1 e 65535 e timeout entre 3 e 60 segundos.")
            if not re.fullmatch(r"\d{2}", plain_fields["password.min_length"]) or not 12 <= int(plain_fields["password.min_length"]) <= 64:
                raise ValueError("O tamanho mínimo da senha deve estar entre 12 e 64 caracteres.")
            for color_key in ("branding.primary", "branding.secondary", "branding.background_start", "branding.background_end", "branding.accent"):
                if not re.fullmatch(r"#[0-9a-fA-F]{6}", plain_fields[color_key]):
                    raise ValueError("As cores devem usar o formato hexadecimal #RRGGBB.")
            if plain_fields["general.timezone"] not in available_timezones():
                raise ValueError("Fuso horário inválido.")
            monitoring_limits = {
                "monitoring.periodic_interval_minutes": (5, 10080, "O intervalo periódico deve estar entre 5 minutos e 7 dias."),
                "monitoring.timeout_seconds": (3, 60, "O timeout deve estar entre 3 e 60 segundos."),
                "monitoring.retries": (0, 5, "As tentativas adicionais devem estar entre 0 e 5."),
                "monitoring.failure_threshold": (1, 10, "O limiar de falhas deve estar entre 1 e 10."),
                "monitoring.repeat_alert_minutes": (15, 10080, "A repetição de alertas deve estar entre 15 minutos e 7 dias."),
            }
            for key, (minimum, maximum, message) in monitoring_limits.items():
                try:
                    number = int(plain_fields[key])
                except (TypeError, ValueError):
                    raise ValueError(message)
                if not minimum <= number <= maximum:
                    raise ValueError(message)
                plain_fields[key] = str(number)
            raw_recipients = re.split(r"[,;\n]+", request.form.get("monitoring_recipients", ""))
            recipients = []
            for raw_recipient in raw_recipients:
                if raw_recipient.strip():
                    recipient = _email(raw_recipient)
                    if recipient not in recipients:
                        recipients.append(recipient)
            plain_fields["monitoring.recipients"] = ",".join(recipients)
            for key, value in plain_fields.items():
                set_setting(key, str(value), user=current_user())
            for key, field in (("entra.client_secret", "client_secret"), ("google.client_secret", "google_client_secret"), ("email.password", "smtp_password")):
                value = request.form.get(field, "")
                if value:
                    set_setting(key, value, secret=True, user=current_user())
            logo = request.files.get("logo")
            if logo and logo.filename:
                content = logo.read(2 * 1024 * 1024 + 1)
                signatures = ((b"\x89PNG\r\n\x1a\n", ".png"), (b"\xff\xd8\xff", ".jpg"), (b"<svg", ".svg"))
                match = next((item for item in signatures if content.lstrip().startswith(item[0])), None)
                if not match or len(content) > 2 * 1024 * 1024:
                    raise ValueError("A logo deve ser PNG, JPG ou SVG e ter no máximo 2 MB.")
                target = Path(current_app.config["BRANDING_ROOT"]) / f"logo{match[1]}"
                for old in Path(current_app.config["BRANDING_ROOT"]).glob("logo.*"):
                    if old.is_file() and old != target:
                        old.unlink()
                target.write_bytes(content)
                set_setting("branding.logo", target.name, user=current_user())
            audit("settings.updated", "settings", "portal", {"changed": list(plain_fields)}, user=current_user())
            db.session.commit()
            current_app.config["ENTRA_TENANT_ID"] = plain_fields["entra.tenant_id"]
            current_app.config["ENTRA_CLIENT_ID"] = plain_fields["entra.client_id"]
            from .settings import get_setting as _get_setting
            entra_secret = _get_setting("entra.client_secret", current_app.config.get("ENTRA_CLIENT_SECRET", ""))
            if plain_fields["entra.tenant_id"] and plain_fields["entra.client_id"] and entra_secret:
                oauth.register(name="entra", client_id=plain_fields["entra.client_id"], client_secret=entra_secret, server_metadata_url=f"https://login.microsoftonline.com/{plain_fields['entra.tenant_id']}/v2.0/.well-known/openid-configuration", client_kwargs={"scope": "openid profile email"}, token_endpoint_auth_method="client_secret_post")
            google_secret = _get_setting("google.client_secret", "")
            if plain_fields["google.client_id"] and google_secret:
                oauth.register(name="google", client_id=plain_fields["google.client_id"], client_secret=google_secret, server_metadata_url="https://accounts.google.com/.well-known/openid-configuration", client_kwargs={"scope": "openid email profile"})
            flash("Configurações atualizadas.", "success")
            return settings_redirect()
        except ValueError as exc:
            db.session.rollback()
            flash(str(exc), "error")
    stored_from = get_setting("email.from", current_app.config.get("SMTP_FROM", ""))
    stored_from_name, stored_from_address = split_sender(stored_from)
    sender_name = get_setting("email.from_name", stored_from_name) or stored_from_name
    sender_address = get_setting("email.from_address", stored_from_address) or stored_from_address or stored_from
    values = {
        "m365_enabled": get_setting("auth.m365_enabled", "True") == "True",
        "google_enabled": get_setting("auth.google_enabled", "False") == "True",
        "local_enabled": get_setting("auth.local_enabled", str(current_app.config.get("LOCAL_AUTH_ENABLED", True))) == "True",
        "tenant_id": get_setting("entra.tenant_id", current_app.config.get("ENTRA_TENANT_ID", "")),
        "client_id": get_setting("entra.client_id", current_app.config.get("ENTRA_CLIENT_ID", "")),
        "google_client_id": get_setting("google.client_id", current_app.config.get("GOOGLE_CLIENT_ID", "")),
        "email_mode": get_setting("email.mode", "smtp"),
        "smtp_provider": get_setting("email.provider", "other"),
        "smtp_host": get_setting("email.host", current_app.config.get("SMTP_HOST", "")),
        "smtp_port": get_setting("email.port", str(current_app.config.get("SMTP_PORT", 587))),
        "smtp_security": get_setting("email.security", "starttls" if get_setting("email.starttls", str(current_app.config["SMTP_STARTTLS"])) == "True" else "none"),
        "smtp_auth_method": get_setting("email.auth_method", "password"),
        "smtp_from_name": sender_name,
        "smtp_from_address": sender_address,
        "smtp_from": format_sender(sender_name, sender_address),
        "smtp_reply_to": get_setting("email.reply_to", ""),
        "smtp_support_address": get_setting("email.support_address", "") or sender_address,
        "smtp_username": get_setting("email.username", current_app.config.get("SMTP_USERNAME", "")),
        "smtp_timeout": get_setting("email.timeout", "15"),
        "smtp_starttls": get_setting("email.starttls", str(current_app.config.get("SMTP_STARTTLS", True))) == "True",
        "company_name": get_setting("branding.company_name", current_app.config.get("COMPANY_NAME", "Sua empresa")),
        "primary_color": get_setting("branding.primary", "#5619a3"),
        "secondary_color": get_setting("branding.secondary", "#7c32c7"),
        "background_start": get_setting("branding.background_start", "#09070d"),
        "background_end": get_setting("branding.background_end", "#180d2c"),
        "background_gradient": get_setting("branding.gradient", "True") == "True",
        "accent_color": get_setting("branding.accent", "#b786f4"),
        "timezone": get_setting("general.timezone", "America/Sao_Paulo"),
        "monitoring_after_publish_enabled": get_setting("monitoring.after_publish_enabled", "True") == "True",
        "monitoring_periodic_enabled": get_setting("monitoring.periodic_enabled", "False") == "True",
        "monitoring_periodic_interval_minutes": get_setting("monitoring.periodic_interval_minutes", "60"),
        "monitoring_timeout_seconds": get_setting("monitoring.timeout_seconds", "12"),
        "monitoring_retries": get_setting("monitoring.retries", "1"),
        "monitoring_failure_threshold": get_setting("monitoring.failure_threshold", "2"),
        "monitoring_repeat_alert_minutes": get_setting("monitoring.repeat_alert_minutes", "240"),
        "monitoring_notify_recovery": get_setting("monitoring.notify_recovery", "True") == "True",
        "monitoring_validate_content": get_setting("monitoring.validate_content", "True") == "True",
        "monitoring_recipients": get_setting("monitoring.recipients", ""),
        "password_min_length": get_setting("password.min_length", "12"),
        "password_require_upper": get_setting("password.require_upper", "True") == "True",
        "password_require_lower": get_setting("password.require_lower", "True") == "True",
        "password_require_number": get_setting("password.require_number", "True") == "True",
        "password_require_symbol": get_setting("password.require_symbol", "True") == "True",
    }
    role_list = _roles_for_form()
    role_permissions = {}
    for role in role_list:
        try:
            role_permissions[role.code] = json.loads(role.permissions or "[]")
        except json.JSONDecodeError:
            role_permissions[role.code] = []
    return render_template(
        "settings.html", values=values, timezones=sorted(available_timezones()),
        settings_section=section, settings_tab=tab,
        secret_info={key: setting_info(key) for key in ("entra.client_secret", "google.client_secret", "email.password")},
        roles=role_list, role_permissions=role_permissions, sectors=Sector.query.order_by(Sector.active.desc(), Sector.name).all(),
        functions=JobFunction.query.order_by(JobFunction.active.desc(), JobFunction.name).all(),
        users=User.query.filter(User.deleted_at.is_(None)).order_by(User.email).all(), permission_options=PERMISSION_OPTIONS,
        custom_themes=[
            {"id": theme.id, "name": theme.name, "config": json.loads(theme.config or "{}")}
            for theme in PortalTheme.query.order_by(PortalTheme.created_at.desc()).all()
        ],
    )


@bp.get("/branding/logo")
@login_required
def branding_logo():
    filename = get_setting("branding.logo", "")
    if not filename or Path(filename).name != filename:
        abort(404)
    path = Path(current_app.config["BRANDING_ROOT"]) / filename
    if not path.is_file():
        abort(404)
    return send_file(path, max_age=300)


@bp.route("/users/new", methods=["GET", "POST"])
@roles_required("super_admin")
def user_new():
    temporary_password = None
    if request.method == "POST":
        try:
            role = request.form.get("role", "editor")
            if not Role.query.filter_by(code=role, active=True).first():
                raise ValueError("Perfil inválido.")
            auth_type = request.form.get("auth_type", "m365")
            if auth_type not in {"m365", "google", "local"}:
                raise ValueError("Tipo de autenticação inválido.")
            email = _email(request.form.get("email", ""))
            username = None
            if auth_type == "local":
                username = _username(request.form.get("username", ""))
                if User.query.filter_by(username=username).first():
                    raise ValueError("Este username já está em uso.")
            first_name = _clean(request.form.get("first_name"), 80)
            last_name = _clean(request.form.get("last_name"), 80)
            display_name = _clean(request.form.get("display_name"), 160) or " ".join(item for item in (first_name, last_name) if item)
            if not display_name:
                raise ValueError("Informe o nome e sobrenome ou um nome de exibição.")
            password = None
            force_change = request.form.get("password_change_required") == "on"
            if auth_type == "local":
                password = request.form.get("password", "")
                if force_change and not password:
                    temporary_password = secrets.token_hex(5)
                    password = temporary_password
                else:
                    _strong_password(password)
                if password != request.form.get("password_confirm", ""):
                    raise ValueError("A confirmação da senha não confere.")
            user = User(
                email=email,
                username=username,
                first_name=first_name,
                last_name=last_name,
                display_name=display_name,
                nickname=_clean(request.form.get("nickname"), 80),
                department=_clean(request.form.get("department"), 120),
                job_title=_clean(request.form.get("job_title"), 120),
                auth_provider=auth_type,
                role=role,
                active=True,
                created_by_id=current_user().id,
                password_hash=generate_password_hash(password) if password else None,
                password_change_required=bool(force_change and auth_type == "local"),
            )
            db.session.add(user)
            db.session.flush()
            avatar_kind, avatar_config = _avatar_form_values(user)
            if request.files.get("avatar"):
                store_uploaded_avatar(user, request.files.get("avatar"))
            elif avatar_kind == "initials":
                clear_uploaded_avatar(user)
            elif avatar_kind in AVATAR_PRESETS:
                user.avatar_kind = avatar_kind
                user.avatar_config = avatar_config
            elif avatar_kind in {"builder", "preset", "custom"}:
                user.avatar_kind = avatar_kind
                user.avatar_config = avatar_config
            audit("user.created", "user", user.id, {"username": user.username, "role": role, "auth_provider": auth_type})
            db.session.commit()
            send_welcome_email(user, temporary_password)
            db.session.commit()
            flash("Usuário criado e e-mail de acesso enviado.", "success")
            return redirect(url_for("panel.settings", section="access", tab="users"))
        except ValueError as exc:
            db.session.rollback()
            flash(str(exc), "error")
    return render_template(
        "user_form.html", user=None, roles=_roles_for_form(), sectors=_sectors_for_form(), functions=_functions_for_form()
    )


@bp.route("/users/<int:user_id>/edit", methods=["GET", "POST"])
@roles_required("super_admin")
def user_edit(user_id: int):
    user = db.get_or_404(User, user_id)
    if user.deleted_at is not None:
        abort(404)
    if request.method == "POST":
        try:
            role = request.form.get("role", user.role)
            selected_role = Role.query.filter_by(code=role, active=True).first()
            if not selected_role:
                raise ValueError("Perfil inválido.")
            if user.role in {"super_admin", "admin", "editor"} and not selected_role.system:
                raise ValueError("Perfis padrão não podem ser convertidos diretamente em perfil personalizado.")
            active = request.form.get("active") == "on"
            if user.role in {"super_admin", "admin"} and (role not in {"super_admin", "admin"} or not active):
                active_admins = User.query.filter(User.role.in_(["super_admin", "admin"]), User.active.is_(True)).count()
                if active_admins <= 1:
                    raise ValueError("O último administrador não pode ser removido.")
            before = {"email": user.email, "username": user.username, "role": user.role, "active": user.active}
            new_email = _email(request.form.get("email", ""))
            if user.entra_oid and new_email != user.email:
                raise ValueError("Contas já vinculadas devem alterar o e-mail no Microsoft 365.")
            user.email = new_email
            new_username = None
            if user.auth_provider == "local":
                new_username = _username(request.form.get("username", user.username or ""))
                duplicate = User.query.filter(User.username == new_username, User.id != user.id).first()
                if duplicate:
                    raise ValueError("Este username já está em uso.")
            user.username = new_username
            user.first_name = _clean(request.form.get("first_name"), 80)
            user.last_name = _clean(request.form.get("last_name"), 80)
            user.display_name = _clean(request.form.get("display_name"), 160) or " ".join(item for item in (user.first_name, user.last_name) if item)
            user.nickname = _clean(request.form.get("nickname"), 80)
            user.department = _clean(request.form.get("department"), 120)
            user.job_title = _clean(request.form.get("job_title"), 120)
            user.role = role
            user.active = active
            password = request.form.get("password", "")
            password_confirm = request.form.get("password_confirm", "")
            if password:
                if user.auth_provider != "local":
                    raise ValueError("A senha desta conta é gerenciada pelo provedor de autenticação.")
                _strong_password(password)
                if password != password_confirm:
                    raise ValueError("A confirmação da senha não confere.")
                user.password_hash = generate_password_hash(password)
                user.password_change_required = False
            if user.auth_provider == "local" and request.form.get("totp_grace_days", "").strip():
                grace_days = _integer(request.form.get("totp_grace_days"), "Dias de tolerância", minimum=0)
                user.totp_grace_until = utcnow() + timedelta(days=grace_days) if grace_days else None
            avatar_kind, avatar_config = _avatar_form_values(user)
            if request.files.get("avatar"):
                store_uploaded_avatar(user, request.files.get("avatar"))
            elif avatar_kind == "initials":
                clear_uploaded_avatar(user)
            elif avatar_kind in AVATAR_PRESETS:
                user.avatar_kind = avatar_kind
                user.avatar_config = avatar_config
            elif avatar_kind in {"builder", "preset", "custom"}:
                user.avatar_kind = avatar_kind
                user.avatar_config = avatar_config
            audit(
                "user.updated",
                "user",
                user.id,
                {"before": before, "after": {"email": user.email, "username": user.username, "role": role, "active": active}},
            )
            return _commit_or_flash("Usuário atualizado.", "panel.settings", section="access", tab="users")
        except ValueError as exc:
            db.session.rollback()
            flash(str(exc), "error")
    return render_template(
        "user_form.html", user=user, roles=_roles_for_form(), sectors=_sectors_for_form(), functions=_functions_for_form()
    )


@bp.post("/users/<int:user_id>/delete")
@roles_required("super_admin")
def user_delete(user_id: int):
    user = db.get_or_404(User, user_id)
    actor = current_user()
    if user.deleted_at is not None:
        abort(404)
    if user.id == actor.id:
        flash("Você não pode excluir o usuário conectado.", "error")
        return redirect(url_for("panel.settings", section="access", tab="users"))
    if user.role == "super_admin" and user.active:
        remaining = User.query.filter(
            User.role == "super_admin",
            User.active.is_(True),
            User.deleted_at.is_(None),
            User.id != user.id,
        ).count()
        if remaining == 0:
            flash("O último Super Admin ativo não pode ser excluído.", "error")
            return redirect(url_for("panel.settings", section="access", tab="users"))
    now = utcnow()
    user.active = False
    user.deleted_at = now
    user.deleted_by_id = actor.id
    SessionToken.query.filter_by(user_id=user.id, revoked_at=None).update(
        {SessionToken.revoked_at: now}, synchronize_session=False
    )
    audit(
        "user.deleted",
        "user",
        user.id,
        {"email": user.email, "role": user.role, "mode": "soft_delete"},
        user=actor,
    )
    return _commit_or_flash(
        "Usuário excluído e sessões revogadas.",
        "panel.settings",
        section="access",
        tab="users",
    )


@bp.post("/users/<int:user_id>/2fa-grace")
@roles_required("admin")
def user_2fa_grace(user_id: int):
    user = db.get_or_404(User, user_id)
    if user.auth_provider != "local":
        flash("A conta externa não usa o 2FA local.", "warning")
        return redirect(url_for("panel.users"))
    try:
        days = _integer(request.form.get("days"), "Dias de tolerância", minimum=0)
        if days > 30:
            raise ValueError("O prazo máximo de tolerância é 30 dias.")
        user.totp_grace_until = utcnow() + timedelta(days=days) if days else None
        audit("user.2fa_grace_updated", "user", user.id, {"days": days}, user=current_user())
        return _commit_or_flash("Prazo de tolerância do 2FA atualizado.", "panel.users")
    except ValueError as exc:
        db.session.rollback()
        flash(str(exc), "error")
        return redirect(url_for("panel.users"))


@bp.post("/users/<int:user_id>/2fa-reset")
@roles_required("admin")
def user_2fa_reset(user_id: int):
    user = db.get_or_404(User, user_id)
    if user.auth_provider != "local":
        flash("A conta externa não usa o 2FA local.", "warning")
        return redirect(url_for("panel.users"))
    user.totp_secret = None
    user.totp_enabled = False
    user.recovery_codes = ""
    user.totp_grace_until = None
    audit("user.2fa_reset", "user", user.id, user=current_user())
    return _commit_or_flash("2FA resetado. O usuário deverá configurar o autenticador no próximo acesso.", "panel.users")


@bp.get("/profile")
@login_required
def profile():
    return render_template("profile.html", user=current_user())


@bp.route("/profile/edit", methods=["GET", "POST"])
@login_required
def profile_edit():
    user = current_user()
    if request.method == "POST":
        display_name = _clean(request.form.get("display_name"), 160)
        password = request.form.get("password", "")
        confirmation = request.form.get("password_confirm", "")
        try:
            if not display_name:
                raise ValueError("Informe um nome de exibição.")
            user.first_name = _clean(request.form.get("first_name"), 80)
            user.last_name = _clean(request.form.get("last_name"), 80)
            user.display_name = display_name
            user.nickname = _clean(request.form.get("nickname"), 80)
            user.department = _clean(request.form.get("department"), 120)
            user.job_title = _clean(request.form.get("job_title"), 120)
            avatar_kind, avatar_config = _avatar_form_values(user)
            if request.files.get("avatar"):
                store_uploaded_avatar(user, request.files.get("avatar"))
            elif avatar_kind == "initials":
                clear_uploaded_avatar(user)
            elif avatar_kind in AVATAR_PRESETS:
                user.avatar_kind = avatar_kind
                user.avatar_config = avatar_config
            elif avatar_kind in {"builder", "preset", "custom"}:
                user.avatar_kind = avatar_kind
                user.avatar_config = avatar_config
            if password:
                if len(password) < 12 or password != confirmation:
                    raise ValueError("A nova senha deve ter 12 caracteres e confirmação idêntica.")
                if not user.password_hash:
                    provider = {"m365": "Microsoft 365", "google": "Google Workspace"}.get(user.auth_provider, "provedor externo")
                    raise ValueError(f"A senha desta conta é gerenciada pelo {provider}.")
                user.password_hash = generate_password_hash(password)
            audit("profile.updated", "user", user.id, {"display_name": display_name}, user=user)
            return _commit_or_flash("Perfil atualizado.", "panel.profile")
        except ValueError as exc:
            db.session.rollback()
            flash(str(exc), "error")
    return render_template("profile_edit.html", user=user, sectors=_sectors_for_form(), functions=_functions_for_form())


@bp.get("/changes")
@login_required
def changes():
    return render_template(
        "changes.html", changes=ChangeRequest.query.order_by(ChangeRequest.created_at.desc()).all()
    )


@bp.get("/notifications")
@login_required
def notifications():
    items = InAppNotification.query.filter_by(user_id=current_user().id).order_by(
        InAppNotification.created_at.desc()
    ).limit(100).all()
    return render_template("notifications.html", notifications=items)


@bp.get("/notifications/feed")
@login_required
def notifications_feed():
    items = InAppNotification.query.filter_by(user_id=current_user().id).order_by(
        InAppNotification.created_at.desc()
    ).limit(10).all()
    return jsonify({"notifications": [{
        "title": item.title,
        "message": item.message,
        "link": item.link,
        "read": item.read_at is not None,
        "created_at": item.created_at.isoformat(),
    } for item in items]})


@bp.post("/notifications/read-all")
@login_required
def notifications_read_all():
    InAppNotification.query.filter_by(user_id=current_user().id, read_at=None).update(
        {"read_at": utcnow()}, synchronize_session=False
    )
    db.session.commit()
    flash("Notificações marcadas como lidas.", "success")
    return redirect(url_for("panel.notifications"))


@bp.get("/users/<int:user_id>/avatar")
@login_required
def user_avatar(user_id: int):
    user = db.get_or_404(User, user_id)
    if current_user().id != user.id and not current_user().is_admin():
        abort(403)
    if user.avatar_kind in {"preset", "custom"}:
        return Response(dicebear_svg(user.avatar_config, user.avatar_kind), mimetype="image/svg+xml")
    if user.avatar_kind == "builder":
        return Response(avatar_svg(user.avatar_config), mimetype="image/svg+xml")
    if user.avatar_kind in AVATAR_PRESETS:
        return Response(avatar_svg(AVATAR_PRESET_CONFIGS[user.avatar_kind]), mimetype="image/svg+xml")
    filename = user.avatar_path or f"{user.id}.jpg"
    if Path(filename).name != filename:
        abort(404)
    path = Path(current_app.config["AVATAR_ROOT"]) / filename
    if not path.is_file():
        abort(404)
    return send_file(path, max_age=300)


@bp.get("/avatars/presets/<preset>")
@login_required
def avatar_preset(preset: str):
    if preset not in AVATAR_PRESET_CONFIGS:
        abort(404)
    return Response(avatar_svg(AVATAR_PRESET_CONFIGS[preset]), mimetype="image/svg+xml")


@bp.get("/avatars/dicebear-preview")
@login_required
def dicebear_preview():
    raw_config = request.args.get("config", "{}")
    config = sanitize_dicebear_config(raw_config, "custom")
    response = Response(dicebear_svg(config, "custom"), mimetype="image/svg+xml")
    response.headers["Cache-Control"] = "no-store"
    return response


@bp.route("/changes/submit", methods=["GET", "POST"])
@login_required
def change_submit():
    if request.method == "POST":
        title = _clean(request.form.get("title"), 180)
        if not title:
            flash("Informe um título.", "error")
            return redirect(url_for("panel.blocks"))
        try:
            change = _create_change_request(
                build_snapshot(),
                title,
                _clean(request.form.get("notes"), 4000),
                current_user(),
            )
            db.session.commit()
            flash("Alteração enviada para aprovação.", "success")
            return redirect(url_for("panel.change_detail", change_id=change.id))
        except ValueError as exc:
            db.session.rollback()
            flash(str(exc), "error")
            return redirect(url_for("panel.blocks"))
    flash("As solicitações são criadas diretamente nas telas de blocos e entradas.", "info")
    return render_template("change_submit.html")


@bp.get("/changes/<int:change_id>")
@login_required
def change_detail(change_id: int):
    change = db.get_or_404(ChangeRequest, change_id)
    validation = validate_snapshot(json.loads(change.snapshot_json))
    return render_template("change_detail.html", change=change, validation=validation)


@bp.post("/changes/<int:change_id>/approve")
@roles_required("admin")
def change_approve(change_id: int):
    change = db.get_or_404(ChangeRequest, change_id)
    if change.status != "pending":
        abort(409)
    if change.requested_by_id == current_user().id:
        flash("O autor não pode aprovar a própria solicitação.", "error")
        return redirect(url_for("panel.change_detail", change_id=change.id))
    schedule_text = _clean(request.form.get("scheduled_for"), 32)
    review_notes = _clean(request.form.get("review_notes"), 4000)
    snapshot = json.loads(change.snapshot_json)
    validation = validate_snapshot(snapshot)
    published_now = False
    try:
        if schedule_text:
            if not validation.valid:
                raise ValueError(
                    "A solicitação contém erros e não pode ser agendada: "
                    + validation.errors[0]
                )
            local_time = datetime.fromisoformat(schedule_text).replace(
                tzinfo=ZoneInfo("America/Sao_Paulo")
            )
            if local_time <= datetime.now(ZoneInfo("America/Sao_Paulo")):
                raise ValueError("O agendamento deve estar no futuro.")
            change.status = "scheduled"
            change.scheduled_for = local_time.astimezone(timezone.utc)
            change.reviewed_by_id = current_user().id
            change.reviewed_at = utcnow()
            change.review_notes = review_notes
            audit("change.scheduled", "change", change.id, {"scheduled_for": local_time.isoformat()})
            message = "Publicação aprovada e agendada."
        else:
            change.review_notes = review_notes
            replace_working_snapshot(snapshot, current_user())
            if validation.valid:
                publication = publish(snapshot, current_user(), change.title, change)
                published_now = True
                message = f"Publicação v{publication.version} concluída."
            else:
                change.status = "approved"
                change.reviewed_by_id = current_user().id
                change.reviewed_at = utcnow()
                message = (
                    "Solicitação aprovada no rascunho. Corrija os erros de validação "
                    "antes de publicar."
                )
        create_in_app_notifications(
            [change.requested_by],
            f"Solicitação #{change.id} aprovada",
            message,
            url_for("panel.change_detail", change_id=change.id),
        )
        send_notification(
            [change.requested_by.email],
            f"[Geofeed] Solicitação #{change.id} aprovada",
            message,
        )
        db.session.commit()
        if published_now:
            run_publication_healthchecks()
        flash(message, "success")
    except ValueError as exc:
        db.session.rollback()
        flash(str(exc), "error")
    return redirect(url_for("panel.change_detail", change_id=change.id))


@bp.post("/changes/<int:change_id>/reject")
@roles_required("admin")
def change_reject(change_id: int):
    change = db.get_or_404(ChangeRequest, change_id)
    if change.status != "pending":
        abort(409)
    if change.requested_by_id == current_user().id:
        abort(403)
    reason = _clean(request.form.get("review_notes"), 4000)
    if not reason:
        flash("Informe o motivo da rejeição.", "error")
        return redirect(url_for("panel.change_detail", change_id=change.id))
    change.status = "rejected"
    change.reviewed_by_id = current_user().id
    change.reviewed_at = utcnow()
    change.review_notes = reason
    audit("change.rejected", "change", change.id, {"reason": reason})
    create_in_app_notifications(
        [change.requested_by],
        f"Solicitação #{change.id} recusada",
        reason,
        url_for("panel.change_detail", change_id=change.id),
    )
    send_notification(
        [change.requested_by.email],
        f"[Geofeed] Solicitação #{change.id} rejeitada",
        reason,
    )
    db.session.commit()
    flash("Solicitação rejeitada.", "success")
    return redirect(url_for("panel.change_detail", change_id=change.id))


@bp.get("/history")
@login_required
def history():
    return render_template(
        "history.html", publications=Publication.query.order_by(Publication.version.desc()).all()
    )


@bp.get("/history/<int:publication_id>")
@login_required
def history_detail(publication_id: int):
    publication = db.get_or_404(Publication, publication_id)
    snapshot = json.loads(publication.snapshot_json)
    previous = Publication.query.filter(Publication.version < publication.version).order_by(
        Publication.version.desc()
    ).first()
    previous_snapshot = json.loads(previous.snapshot_json) if previous else None
    return render_template(
        "history_detail.html",
        publication=publication,
        snapshot=snapshot,
        diff=diff_snapshots(previous_snapshot, snapshot),
    )


@bp.post("/history/<int:publication_id>/restore")
@roles_required("admin")
def history_restore(publication_id: int):
    publication = db.get_or_404(Publication, publication_id)
    snapshot = json.loads(publication.snapshot_json)
    replace_working_snapshot(snapshot, current_user())
    db.session.commit()
    flash(
        f"A versão {publication.version} foi restaurada como rascunho. Revise e publique quando estiver pronto.",
        "success",
    )
    return redirect(url_for("panel.dashboard"))


@bp.get("/audit")
@roles_required("admin", "viewer")
def audit_logs():
    search = _clean(request.args.get("q"), 120)
    date_from = _clean(request.args.get("date_from"), 10)
    date_to = _clean(request.args.get("date_to"), 10)
    query = AuditLog.query.outerjoin(User)
    if search:
        query = query.filter(
            or_(
                AuditLog.action.ilike(f"%{search}%"),
                AuditLog.entity_type.ilike(f"%{search}%"),
                AuditLog.details.ilike(f"%{search}%"),
                User.email.ilike(f"%{search}%"),
            )
        )
    try:
        if date_from:
            query = query.filter(AuditLog.created_at >= datetime.fromisoformat(date_from))
        if date_to:
            end = datetime.fromisoformat(date_to).replace(hour=23, minute=59, second=59)
            query = query.filter(AuditLog.created_at <= end)
    except ValueError:
        flash("Período inválido; o filtro de data foi ignorado.", "warning")
    logs = query.order_by(AuditLog.created_at.desc()).limit(500).all()
    return render_template(
        "audit.html", logs=logs, search=search, date_from=date_from, date_to=date_to
    )


@bp.get("/monitoring")
@login_required
def monitoring():
    checks = HealthCheck.query.order_by(HealthCheck.checked_at.desc()).limit(500).all()
    notifications = NotificationLog.query.order_by(NotificationLog.created_at.desc()).limit(100).all()
    return render_template("monitoring.html", checks=checks, notifications=notifications)


@bp.post("/monitoring/run")
@roles_required("admin")
@limiter.limit("10 per hour")
def monitoring_run():
    ok, total = run_healthchecks(trigger="manual")
    audit("monitoring.executed", details={"ok": ok, "total": total})
    db.session.commit()
    flash(f"Monitoramento concluído: {ok}/{total} arquivos disponíveis.", "success" if ok == total else "warning")
    return redirect(url_for("panel.monitoring"))
