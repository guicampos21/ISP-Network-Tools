from __future__ import annotations

import io
import hashlib
import hmac
import ipaddress
import json
import re
import secrets
import unicodedata
import zipfile
from datetime import datetime, time, timedelta, timezone
from decimal import Decimal, InvalidOperation
from pathlib import Path
from types import SimpleNamespace
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
from sqlalchemy import func, or_, select
from sqlalchemy.exc import IntegrityError
from werkzeug.security import generate_password_hash
import requests

from . import csrf, limiter, oauth
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
    Customer,
    FeedEntry,
    Group,
    HealthCheck,
    InAppNotification,
    IpamAllocation,
    IpamApprovalRequest,
    IpamEquipment,
    NetworkBlock,
    NotificationLog,
    Publication,
    PortalTheme,
    PopDc,
    PopAccessWindow,
    Role,
    Sector,
    ServiceCatalogItem,
    SessionToken,
    JobFunction,
    User,
    customer_service_items,
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
from .security import application_required, audit, current_user, login_required, normalize_email, permission_required, roles_required
from .settings import get_setting, set_setting, setting_info
from isp_shared.sso import issue_handoff


bp = Blueprint("panel", __name__)

PERMISSION_OPTIONS = {
    "app.admin_center.access": "Abrir o Admin Center",
    "app.ipam_geofeed.access": "Abrir o IPAM/Geofeed",
    "app.isp_network_health.access": "Abrir o ISP Network Health",
    "dashboard.view": "Visualizar o Dashboard",
    "audit.view": "Visualizar a Auditoria",
    "content.edit": "Editar empresas, blocos e entradas",
    "approvals.review": "Aprovar ou rejeitar alterações",
    "monitoring.run": "Executar monitoramento",
    "admin.access": "Acessar recursos administrativos",
    "catalog.companies.view": "Visualizar cadastro de empresas",
    "catalog.companies.manage": "Administrar cadastro de empresas",
    "catalog.customers.view": "Visualizar cadastro de clientes",
    "catalog.customers.manage": "Administrar cadastro de clientes",
    "catalog.pops.view": "Visualizar cadastro de POPs/DCs",
    "catalog.pops.manage": "Administrar cadastro de POPs/DCs",
    "catalog.services.view": "Visualizar Catálogo de Serviços",
    "catalog.services.manage": "Administrar Catálogo de Serviços",
    "ipam.private.manage": "Administrar recursos IP privados",
    "ipam.public.submit": "Enviar recursos IP públicos para aprovação",
    "ipam.public.approve": "Aprovar recursos IP públicos",
    "ipam.public.reject": "Rejeitar recursos IP públicos",
    "ipam.equipment.manage": "Administrar equipamentos do IPAM",
    "ipam.publish": "Publicar o Geofeed",
    "health.view": "Visualizar análises de saúde",
    "health.run": "Executar análises de saúde",
    "health.report.export": "Exportar relatórios de saúde",
    "users.manage": "Administrar usuários",
    "profiles.manage": "Administrar perfis",
    "groups.manage": "Administrar grupos",
    "settings.manage": "Administrar configurações",
}

CUSTOMER_SERVICE_STATUSES = {
    "suspended": "Suspenso",
    "active": "Ativo",
    "canceled": "Cancelado",
}


def _customer_service_statuses(customer: Customer | None) -> dict[int, str]:
    if not customer or not customer.id:
        return {}
    rows = db.session.execute(
        select(customer_service_items.c.service_id, customer_service_items.c.status).where(
            customer_service_items.c.customer_id == customer.id
        )
    ).all()
    return {
        int(service_id): status if status in CUSTOMER_SERVICE_STATUSES else "active"
        for service_id, status in rows
    }


def _apply_customer_service_statuses(customer: Customer, statuses: dict[int, str]) -> None:
    db.session.flush()
    for service_id, status in statuses.items():
        db.session.execute(
            customer_service_items.update()
            .where(
                customer_service_items.c.customer_id == customer.id,
                customer_service_items.c.service_id == service_id,
            )
            .values(status=status)
        )


def _customer_requires_second_approach(customer: Customer | None) -> bool:
    """Return whether an active customer service requires two access paths."""
    if not customer or not customer.id:
        return False
    rows = db.session.execute(
        select(ServiceCatalogItem.name, ServiceCatalogItem.active, customer_service_items.c.status)
        .join(customer_service_items, customer_service_items.c.service_id == ServiceCatalogItem.id)
        .where(customer_service_items.c.customer_id == customer.id)
    ).all()
    return any(
        status == "active" and active and "segunda abordagem" in (name or "").casefold()
        for name, active, status in rows
    )

IPAM_STATUSES = {
    "available": "Disponível",
    "allocated": "Alocado",
    "reserved": "Reservado",
    "blocked": "Bloqueado",
    "decommissioned": "Desativado",
}

WEEKDAYS = (
    ("mon", "Segunda-feira"),
    ("tue", "Terça-feira"),
    ("wed", "Quarta-feira"),
    ("thu", "Quinta-feira"),
    ("fri", "Sexta-feira"),
    ("sat", "Sábado"),
    ("sun", "Domingo"),
)
WEEKDAY_CODES = {code for code, _label in WEEKDAYS}
BATTERY_MAX_MINUTES = 72 * 60

IPAM_AUDIT_APPLICATIONS = {
    "admin_center": "Admin Center",
    "ipam_geofeed": "IPAM/Geofeed",
    "geofeed_public": "Geofeed público",
    "isp_network_health": "ISP Network Health",
}


def _ipam_text(value: str | None, limit: int = 255) -> str:
    value = _clean(value, limit)
    if any(ord(character) < 32 and character not in {"\t"} for character in value):
        raise ValueError("O texto contém caracteres de controle inválidos.")
    return value


def _ipam_coordinate(value: str | None, label: str, minimum: float, maximum: float) -> Decimal | None:
    raw = _clean(value, 32)
    if not raw:
        return None
    try:
        number = Decimal(raw)
    except InvalidOperation as exc:
        raise ValueError(f"{label} inválida.") from exc
    if not number.is_finite() or number < Decimal(str(minimum)) or number > Decimal(str(maximum)):
        raise ValueError(f"{label} inválida.")
    return number.quantize(Decimal("0.0000001"))


def _cnpj(value: str | None) -> str:
    """Normalize and validate a Brazilian CNPJ without accepting placeholders."""
    digits = re.sub(r"\D", "", value or "")
    if len(digits) != 14 or len(set(digits)) == 1:
        raise ValueError("Informe um CNPJ válido com 14 dígitos.")
    for length, weights in ((12, (5, 4, 3, 2, 9, 8, 7, 6, 5, 4, 3, 2)), (13, (6, 5, 4, 3, 2, 9, 8, 7, 6, 5, 4, 3, 2))):
        total = sum(int(digits[index]) * weight for index, weight in enumerate(weights))
        digit = 0 if total % 11 < 2 else 11 - (total % 11)
        if int(digits[length]) != digit:
            raise ValueError("Informe um CNPJ válido.")
    return f"{digits[:2]}.{digits[2:5]}.{digits[5:8]}/{digits[8:12]}-{digits[12:]}"


def _format_time(value: time | None) -> str:
    return value.strftime("%H:%M") if value else ""


def battery_autonomy_label(minutes: int | None) -> str:
    if minutes is None:
        return "Não informado"
    if minutes == 0:
        return "Não possui autonomia"
    if minutes == -1:
        return "Superior a 72 horas"
    return f"{minutes // 60:02d}:{minutes % 60:02d}"


def access_window_label(window: PopAccessWindow) -> str:
    days = [label[:3] for code, label in WEEKDAYS if code in (window.weekdays or "").split(",")]
    end_suffix = " (+1 dia)" if window.end_time <= window.start_time else ""
    return f"{', '.join(days)} · {_format_time(window.start_time)}–{_format_time(window.end_time)}{end_suffix}"


def _parse_time(value: str | None, label: str) -> time:
    try:
        return datetime.strptime(_clean(value, 5), "%H:%M").time()
    except ValueError as exc:
        raise ValueError(f"Informe um horário válido para {label}.") from exc


def _parse_access_windows() -> tuple[bool, list[dict]]:
    always_open = request.form.get("access_24h") == "on"
    if always_open:
        return True, []
    try:
        count = max(0, min(int(request.form.get("window_count", "0") or 0), 32))
    except ValueError as exc:
        raise ValueError("Quantidade de janelas de acesso inválida.") from exc
    windows: list[dict] = []
    segments: list[tuple[int, int, int]] = []
    weekday_index = {code: index for index, (code, _label) in enumerate(WEEKDAYS)}
    for index in range(count):
        days = [code for code in request.form.getlist(f"window_{index}_days") if code in WEEKDAY_CODES]
        if not days:
            raise ValueError(f"Selecione ao menos um dia na janela {index + 1}.")
        start = _parse_time(request.form.get(f"window_{index}_start"), "início")
        end = _parse_time(request.form.get(f"window_{index}_end"), "término")
        if start == end:
            raise ValueError("O horário inicial e final não podem ser iguais; use 24h para acesso contínuo.")
        start_minutes = start.hour * 60 + start.minute
        end_minutes = end.hour * 60 + end.minute
        for day in days:
            day_index = weekday_index[day]
            duration_end = end_minutes if end_minutes > start_minutes else end_minutes + 1440
            segments.append((day_index, start_minutes, duration_end))
            if duration_end > 1440:
                segments.append(((day_index + 1) % 7, 0, duration_end - 1440))
        windows.append({"weekdays": ",".join(days), "start_time": start, "end_time": end})
    for current_index, (day, start, end) in enumerate(segments):
        for other_day, other_start, other_end in segments[current_index + 1:]:
            if day == other_day and max(start, other_start) < min(end, other_end):
                raise ValueError("As janelas de acesso do POP/DC não podem se sobrepor.")
    return False, windows


def _ipam_prefix(value: str | None, resource_kind: str) -> str:
    raw = _ipam_text(value, 64)
    try:
        if resource_kind == "ip":
            return str(ipaddress.ip_address(raw))
        canonical = ipaddress.ip_network(raw, strict=False)
        if str(canonical) != raw:
            raise ValueError(
                f"O prefixo {raw} não inicia no limite da sub-rede /{canonical.prefixlen}. "
                f"Use {canonical}."
            )
        return str(canonical)
    except ValueError as exc:
        if str(exc).startswith("O prefixo "):
            raise
        label = "endereço IP" if resource_kind == "ip" else "bloco CIDR"
        raise ValueError(f"Informe um {label} válido e alinhado.") from exc


def _ipam_network(prefix: str, resource_kind: str) -> ipaddress._BaseNetwork:
    if resource_kind == "ip":
        address = ipaddress.ip_address(prefix)
        return ipaddress.ip_network(f"{prefix}/{address.max_prefixlen}", strict=True)
    return ipaddress.ip_network(prefix, strict=True)


def _ipam_effective_statuses() -> dict[int, str]:
    """Return display statuses for parents whose descendants are in use.

    The stored status remains the source of truth for editing and filtering.
    This extra status is only a read-time indication that a parent contains
    allocated descendants or published child prefixes.
    """
    allocations = IpamAllocation.query.filter(IpamAllocation.status != "decommissioned").all()
    networks: list[tuple[IpamAllocation, ipaddress._BaseNetwork]] = []
    for allocation in allocations:
        try:
            networks.append((allocation, _ipam_network(allocation.prefix, allocation.resource_kind)))
        except ValueError:
            continue

    published_networks: list[ipaddress._BaseNetwork] = []
    snapshot = latest_published_snapshot() or {}
    for block in snapshot.get("blocks", []):
        if not block.get("active"):
            continue
        for entry in block.get("entries", []):
            try:
                published_networks.append(ipaddress.ip_network(str(entry.get("prefix", "")), strict=True))
            except (TypeError, ValueError):
                continue

    statuses: dict[int, str] = {}
    for allocation, network in networks:
        has_allocated_child = any(
            candidate.id != allocation.id
            and candidate.scope == allocation.scope
            and candidate.approval_status == "approved"
            and candidate.status == "allocated"
            and candidate_network.version == network.version
            and candidate_network != network
            and candidate_network.subnet_of(network)
            for candidate, candidate_network in networks
        )
        has_published_child = any(
            candidate.version == network.version
            and candidate != network
            and candidate.subnet_of(network)
            for candidate in published_networks
        )
        statuses[allocation.id] = "in_use" if has_allocated_child or has_published_child else allocation.status
    return statuses


def _classify_ipam_network(network: ipaddress._BaseNetwork) -> str:
    """Classify a network from its address properties, without user input."""
    special_networks = (
        ipaddress.ip_network("192.0.2.0/24"),
        ipaddress.ip_network("198.51.100.0/24"),
        ipaddress.ip_network("203.0.113.0/24"),
        ipaddress.ip_network("2001:db8::/32"),
    )
    if any(network.version == item.version and network.subnet_of(item) for item in special_networks):
        return "special"
    first = network.network_address
    if any((first.is_loopback, first.is_link_local, first.is_multicast, first.is_reserved, first.is_unspecified)):
        return "special"
    if network.is_private:
        return "private"
    if network.is_global:
        return "public"
    return "special"


def _ipam_check_overlap(values: dict, allocation_id: int | None = None) -> None:
    candidate = _ipam_network(values["prefix"], values["resource_kind"])
    for existing in IpamAllocation.query.filter_by(scope=values["scope"]).all():
        if allocation_id is not None and existing.id == allocation_id:
            continue
        try:
            existing_network = _ipam_network(existing.prefix, existing.resource_kind)
        except ValueError:
            continue
        if candidate.version == existing_network.version and candidate.overlaps(existing_network):
            is_hierarchical_allocation = bool(values.get("parent_id")) and candidate != existing_network and (
                candidate.subnet_of(existing_network) or existing_network.subnet_of(candidate)
            )
            if is_hierarchical_allocation:
                continue
            raise ValueError(
                f"O recurso se sobrepõe à alocação existente {existing.prefix} na classificação {values['scope']}."
            )


def _company_values(company: Company | None = None) -> dict:
    latitude = _ipam_coordinate(request.form.get("latitude"), "Latitude", -90, 90)
    longitude = _ipam_coordinate(request.form.get("longitude"), "Longitude", -180, 180)
    if (latitude is None) != (longitude is None):
        raise ValueError("Informe latitude e longitude juntas.")
    values = {
        "name": _ipam_text(request.form.get("name"), 120),
        "cnpj": _cnpj(request.form.get("cnpj")),
        "address": _ipam_text(request.form.get("address"), 255),
        "latitude": latitude,
        "longitude": longitude,
        "default_asn": _integer(request.form.get("default_asn"), "ASN"),
        "contact_email": _email(request.form.get("contact_email", ""), required=False),
        "contact_phone": _ipam_text(request.form.get("contact_phone"), 64),
        "active": request.form.get("active") == "on",
    }
    if not values["name"]:
        raise ValueError("A razão social é obrigatória.")
    duplicate = Company.query.filter(Company.cnpj == values["cnpj"])
    if company:
        duplicate = duplicate.filter(Company.id != company.id)
        for key, value in values.items():
            setattr(company, key, value)
    if duplicate.first():
        raise ValueError("Já existe uma empresa com este CNPJ.")
    return values


def _customer_values(customer: Customer | None = None) -> dict:
    cnpj = _cnpj(request.form.get("cnpj"))
    selected_ids: set[int] = set()
    for raw_id in request.form.getlist("service_ids"):
        try:
            selected_ids.add(int(raw_id))
        except (TypeError, ValueError) as exc:
            raise ValueError("Serviço selecionado inválido.") from exc
    active_services = ServiceCatalogItem.query.filter(
        ServiceCatalogItem.id.in_(selected_ids), ServiceCatalogItem.active.is_(True)
    ).all() if selected_ids else []
    existing_ids = {service.id for service in customer.services} if customer else set()
    if len(active_services) != len(selected_ids):
        inactive_existing = selected_ids - {service.id for service in active_services}
        if not inactive_existing.issubset(existing_ids):
            raise ValueError("Selecione somente serviços ativos do catálogo.")
        services = ServiceCatalogItem.query.filter(ServiceCatalogItem.id.in_(selected_ids)).all()
    else:
        services = active_services
    service_statuses = {}
    for service in services:
        status = request.form.get(f"service_status_{service.id}", "active")
        if status not in CUSTOMER_SERVICE_STATUSES:
            raise ValueError("Status de serviço contratado inválido.")
        service_statuses[service.id] = status
    latitude = _ipam_coordinate(request.form.get("latitude"), "Latitude", -90, 90)
    longitude = _ipam_coordinate(request.form.get("longitude"), "Longitude", -180, 180)
    if (latitude is None) != (longitude is None):
        raise ValueError("Informe latitude e longitude juntas.")
    values = {
        "name": _ipam_text(request.form.get("name"), 160),
        "cnpj": cnpj,
        "address": _ipam_text(request.form.get("address"), 255),
        "city": _ipam_text(request.form.get("city"), 120),
        "state": _ipam_text(request.form.get("state"), 80),
        "postal_code": _ipam_text(request.form.get("postal_code"), 32),
        "latitude": latitude,
        "longitude": longitude,
        "contact_name": _ipam_text(request.form.get("contact_name"), 160),
        "contact_email": _email(request.form.get("contact_email", ""), required=False),
        "contact_phone": _ipam_text(request.form.get("contact_phone"), 64),
        "notes": _ipam_text(request.form.get("notes"), 4000),
        "active": request.form.get("active") == "on",
    }
    if not values["name"]:
        raise ValueError("A razão social é obrigatória.")
    duplicate = Customer.query.filter(Customer.cnpj == cnpj)
    if customer:
        duplicate = duplicate.filter(Customer.id != customer.id)
        for key, value in values.items():
            setattr(customer, key, value)
        customer.document = cnpj
        customer.services = services
    if duplicate.first():
        raise ValueError("Já existe um cliente com este CNPJ.")
    values["document"] = cnpj
    values["services"] = services
    values["service_statuses"] = service_statuses
    return values


def _pop_dc_values(pop: PopDc | None = None) -> dict:
    always_open, access_windows = _parse_access_windows()
    battery_raw = _clean(request.form.get("battery_autonomy_minutes"), 8)
    try:
        battery_minutes = int(battery_raw or "0")
    except ValueError as exc:
        raise ValueError("Autonomia de baterias/UPS inválida.") from exc
    if battery_minutes not in {0, -1} and (battery_minutes < 30 or battery_minutes > BATTERY_MAX_MINUTES or battery_minutes % 30):
        raise ValueError("Selecione uma autonomia em intervalos de 30 minutos até 72 horas.")
    primary_edge_router_id = _clean(request.form.get("primary_edge_router_id"), 16) or None
    primary_edge_router = db.session.get(IpamEquipment, int(primary_edge_router_id)) if primary_edge_router_id else None
    if primary_edge_router and (
        not primary_edge_router.active
        or primary_edge_router.equipment_type != "edge_router"
        or (pop and primary_edge_router.pop_id not in {None, pop.id})
    ):
        raise ValueError("Selecione um roteador de borda ativo e pertencente a este POP/DC.")
    values = {
        "name": _ipam_text(request.form.get("name"), 160),
        "code": _ipam_text(request.form.get("code"), 64).upper(),
        "address": _ipam_text(request.form.get("address"), 255),
        "city": _ipam_text(request.form.get("city"), 120),
        "state": _ipam_text(request.form.get("state"), 80),
        "postal_code": _ipam_text(request.form.get("postal_code"), 32),
        "latitude": _ipam_coordinate(request.form.get("latitude"), "Latitude", -90, 90),
        "longitude": _ipam_coordinate(request.form.get("longitude"), "Longitude", -180, 180),
        "contact_name": _ipam_text(request.form.get("contact_name"), 160),
        "contact_email": _email(request.form.get("contact_email", ""), required=False),
        "contact_phone": _ipam_text(request.form.get("contact_phone"), 64),
        "access_hours": "",
        "battery_autonomy": battery_autonomy_label(battery_minutes),
        "access_24h": always_open,
        "battery_autonomy_minutes": battery_minutes,
        "primary_edge_router_id": primary_edge_router.id if primary_edge_router else None,
        "access_windows": access_windows,
        "notes": _ipam_text(request.form.get("notes"), 4000),
        "active": request.form.get("active") == "on",
    }
    if not values["name"] or not values["code"]:
        raise ValueError("Nome e código do POP/DC são obrigatórios.")
    if (values["latitude"] is None) != (values["longitude"] is None):
        raise ValueError("Informe latitude e longitude juntas.")
    if pop:
        for key, value in values.items():
            if key != "access_windows":
                setattr(pop, key, value)
        pop.access_windows.clear()
        pop.access_windows.extend(PopAccessWindow(**window) for window in access_windows)
    return values


IPAM_INHERITED_FIELDS = (
    "company_id", "geofeed_region", "vlan", "vrf", "customer_id",
    "pop_id", "pop_2_id", "access_type", "access_type_2", "router_id",
    "router_2_id", "switch_id", "switch_2_id", "cpe_id", "access_point_id",
    "access_point_2_id", "st_id", "st_2_id",
)
IPAM_PUBLIC_INHERITED_FIELDS = {"company_id", "geofeed_region"}
IPAM_EFFECTIVE_FIELDS = IPAM_INHERITED_FIELDS + (
    "allocation_address", "latitude", "longitude",
)


def _ipam_geofeed_region(source_block: NetworkBlock | None, network: ipaddress._BaseNetwork) -> str:
    """Return the most specific state/region found in the current Geofeed."""
    if not source_block:
        return ""
    best = None
    best_prefixlen = -1
    for entry in source_block.entries:
        try:
            entry_network = ipaddress.ip_network(entry.prefix, strict=True)
        except ValueError:
            continue
        if entry_network.version == network.version and network.subnet_of(entry_network):
            if entry_network.prefixlen > best_prefixlen and entry.region:
                best = entry.region
                best_prefixlen = entry_network.prefixlen
    return best or ""


def _ipam_effective_operational_values(allocation: IpamAllocation | None) -> tuple[dict, dict]:
    values = {}
    sources = {}
    current = allocation
    visited = set()
    while current and current.id not in visited:
        visited.add(current.id)
        for field in IPAM_EFFECTIVE_FIELDS:
            if field in {"allocation_address", "latitude", "longitude"} and current is not allocation:
                continue
            value = getattr(current, field, None)
            if field not in values and value not in {None, ""}:
                values[field] = value
                sources[field] = current.prefix
        current = current.parent
    return values, sources


def _ipam_child_inherited_values(
    parent: IpamAllocation | None, target_scope: str | None
) -> tuple[dict, dict]:
    """Return the values a child may inherit for its calculated scope."""
    values, sources = _ipam_effective_operational_values(parent)
    if target_scope == "public":
        values = {field: value for field, value in values.items() if field in IPAM_PUBLIC_INHERITED_FIELDS}
        sources = {field: source for field, source in sources.items() if field in IPAM_PUBLIC_INHERITED_FIELDS}
    return values, sources


def _ipam_allocation_values() -> dict:
    resource_kind = _ipam_text(request.form.get("resource_kind"), 16).lower()
    if resource_kind not in {"block", "ip"}:
        raise ValueError("Tipo de recurso IPAM inválido.")
    status = _ipam_text(request.form.get("status"), 24).lower()
    if status not in IPAM_STATUSES:
        raise ValueError("Status do recurso IPAM inválido.")
    source_block_id = request.form.get("source_block_id", "").strip()
    company_id = request.form.get("company_id", "").strip()
    parent_id = request.form.get("parent_id", "").strip()
    customer_id = request.form.get("customer_id", "").strip()
    pop_id = request.form.get("pop_id", "").strip()
    pop_2_id = request.form.get("pop_2_id", "").strip()
    access_type = _ipam_text(request.form.get("access_type"), 16).lower() or "fiber"
    access_type_2 = _ipam_text(request.form.get("access_type_2"), 16).lower() or "fiber"
    router_id = request.form.get("router_id", "").strip()
    router_2_id = request.form.get("router_2_id", "").strip()
    switch_id = request.form.get("switch_id", "").strip()
    switch_2_id = request.form.get("switch_2_id", "").strip()
    cpe_id = request.form.get("cpe_id", "").strip()
    access_point_id = request.form.get("access_point_id", "").strip()
    access_point_2_id = request.form.get("access_point_2_id", "").strip()
    st_id = request.form.get("st_id", "").strip()
    st_2_id = request.form.get("st_2_id", "").strip()
    source_block = db.session.get(NetworkBlock, int(source_block_id)) if source_block_id else None
    company = db.session.get(Company, int(company_id)) if company_id else None
    parent = db.session.get(IpamAllocation, int(parent_id)) if parent_id else None
    customer = db.session.get(Customer, int(customer_id)) if customer_id else None
    pop = db.session.get(PopDc, int(pop_id)) if pop_id else None
    pop_2 = db.session.get(PopDc, int(pop_2_id)) if pop_2_id else None
    router = db.session.get(IpamEquipment, int(router_id)) if router_id else None
    router_2 = db.session.get(IpamEquipment, int(router_2_id)) if router_2_id else None
    switch = db.session.get(IpamEquipment, int(switch_id)) if switch_id else None
    switch_2 = db.session.get(IpamEquipment, int(switch_2_id)) if switch_2_id else None
    cpe = db.session.get(IpamEquipment, int(cpe_id)) if cpe_id else None
    access_point = db.session.get(IpamEquipment, int(access_point_id)) if access_point_id else None
    access_point_2 = db.session.get(IpamEquipment, int(access_point_2_id)) if access_point_2_id else None
    st = db.session.get(IpamEquipment, int(st_id)) if st_id else None
    st_2 = db.session.get(IpamEquipment, int(st_2_id)) if st_2_id else None
    if source_block_id and not source_block:
        raise ValueError("Bloco Geofeed de referência inválido.")
    if company_id and (not company or not company.active):
        raise ValueError("Empresa inválida.")
    if parent_id and (not parent or parent.resource_kind != "block" or parent.status == "decommissioned"):
        raise ValueError("Bloco pai inválido.")
    prefix = _ipam_prefix(request.form.get("prefix"), resource_kind)
    resource_network = _ipam_network(prefix, resource_kind)
    scope = _classify_ipam_network(resource_network)
    inherited, _inherited_sources = _ipam_child_inherited_values(parent, scope)
    customer_id = str(inherited.get("customer_id") or customer_id)
    pop_id = str(inherited.get("pop_id") or pop_id)
    pop_2_id = str(inherited.get("pop_2_id") or pop_2_id)
    access_type = str(inherited.get("access_type") or access_type)
    access_type_2 = str(inherited.get("access_type_2") or access_type_2)
    router_id = str(inherited.get("router_id") or router_id)
    router_2_id = str(inherited.get("router_2_id") or router_2_id)
    switch_id = str(inherited.get("switch_id") or switch_id)
    switch_2_id = str(inherited.get("switch_2_id") or switch_2_id)
    cpe_id = str(inherited.get("cpe_id") or cpe_id)
    access_point_id = str(inherited.get("access_point_id") or access_point_id)
    access_point_2_id = str(inherited.get("access_point_2_id") or access_point_2_id)
    st_id = str(inherited.get("st_id") or st_id)
    st_2_id = str(inherited.get("st_2_id") or st_2_id)
    customer = db.session.get(Customer, int(customer_id)) if customer_id else None
    pop = db.session.get(PopDc, int(pop_id)) if pop_id else None
    pop_2 = db.session.get(PopDc, int(pop_2_id)) if pop_2_id else None
    router = db.session.get(IpamEquipment, int(router_id)) if router_id else None
    router_2 = db.session.get(IpamEquipment, int(router_2_id)) if router_2_id else None
    switch = db.session.get(IpamEquipment, int(switch_id)) if switch_id else None
    switch_2 = db.session.get(IpamEquipment, int(switch_2_id)) if switch_2_id else None
    cpe = db.session.get(IpamEquipment, int(cpe_id)) if cpe_id else None
    access_point = db.session.get(IpamEquipment, int(access_point_id)) if access_point_id else None
    access_point_2 = db.session.get(IpamEquipment, int(access_point_2_id)) if access_point_2_id else None
    st = db.session.get(IpamEquipment, int(st_id)) if st_id else None
    st_2 = db.session.get(IpamEquipment, int(st_2_id)) if st_2_id else None
    if customer_id and not customer:
        raise ValueError("Cliente inválido.")
    if customer and not customer.active:
        raise ValueError("O cliente selecionado está inativo.")
    if pop_id and not pop:
        raise ValueError("POP/DC inválido.")
    if pop_2_id and not pop_2:
        raise ValueError("Segundo POP/DC inválido.")
    if pop and pop_2 and pop.id == pop_2.id:
        raise ValueError("A segunda abordagem deve usar um POP/DC diferente do primeiro.")
    if access_type not in {"fiber", "radio"} or access_type_2 not in {"fiber", "radio"}:
        raise ValueError("Tipo de abordagem inválido.")

    def validate_equipment(item, raw_id, types, label, expected_pop=None, expected_customer=None):
        if not raw_id:
            return
        if not item or not item.active or item.equipment_type not in types:
            raise ValueError(f"{label} inválido.")
        if expected_pop and item.pop_id not in {None, expected_pop.id}:
            raise ValueError(f"{label} não pertence ao POP/DC selecionado.")
        if expected_customer and item.customer_id not in {None, expected_customer.id}:
            raise ValueError(f"{label} não pertence ao cliente selecionado.")

    validate_equipment(router, router_id, {"router"}, "Roteador POP", pop)
    validate_equipment(router_2, router_2_id, {"router"}, "Segundo roteador POP", pop_2)
    validate_equipment(switch, switch_id, {"switch"}, "Switch POP", pop)
    validate_equipment(switch_2, switch_2_id, {"switch"}, "Segundo switch POP", pop_2)
    validate_equipment(cpe, cpe_id, {"cpe"}, "CPE", expected_customer=customer)
    validate_equipment(access_point, access_point_id, {"radio_ap"}, "Rádio AP", pop, customer)
    validate_equipment(access_point_2, access_point_2_id, {"radio_ap"}, "Segundo rádio AP", pop_2, customer)
    validate_equipment(st, st_id, {"radio_st"}, "Rádio cliente (ST)", pop, customer)
    validate_equipment(st_2, st_2_id, {"radio_st"}, "Segundo rádio cliente (ST)", pop_2, customer)

    if pop and not router:
        raise ValueError("Selecione o Roteador POP da primeira abordagem.")
    if pop_2 and not router_2:
        raise ValueError("Selecione o Roteador POP da segunda abordagem.")
    requires_second = _customer_requires_second_approach(customer)
    if requires_second and not customer:
        raise ValueError("Selecione o cliente para um serviço de Segunda abordagem.")
    if requires_second and not pop:
        raise ValueError("Clientes com serviço de Segunda abordagem precisam da primeira abordagem.")
    if requires_second and not pop_2:
        raise ValueError("O serviço ativo de Segunda abordagem exige um segundo POP/DC.")
    if requires_second and not router_2:
        raise ValueError("O serviço ativo de Segunda abordagem exige o segundo Roteador POP.")
    if requires_second and not cpe:
        raise ValueError("O serviço ativo de Segunda abordagem exige uma CPE vinculada ao cliente.")
    if (pop_2 or requires_second) and not customer:
        raise ValueError("Selecione o cliente antes de cadastrar a segunda abordagem.")
    if cpe and customer and cpe.customer_id not in {None, customer.id}:
        raise ValueError("A CPE selecionada pertence a outro cliente.")
    if cpe and cpe.router_id and router and cpe.router_id not in {router.id, router_2.id if router_2 else None}:
        raise ValueError("A CPE não está vinculada ao Roteador POP selecionado.")
    if cpe and cpe.secondary_router_id and router_2 and cpe.secondary_router_id != router_2.id:
        raise ValueError("A segunda abordagem da CPE não corresponde ao segundo Roteador POP.")

    for access_label, access_kind, ap, radio_st in (
        ("primeira", access_type, access_point, st),
        ("segunda", access_type_2, access_point_2, st_2),
    ):
        if access_kind == "radio" and (not ap or not radio_st):
            raise ValueError(f"A abordagem {access_label} via rádio exige um AP e um rádio cliente (ST).")
        if access_kind == "fiber" and (ap or radio_st):
            raise ValueError(f"A abordagem {access_label} via fibra não pode ter AP ou rádio cliente.")
        if radio_st and (not cpe or radio_st.cpe_id not in {None, cpe.id}):
            raise ValueError(f"O rádio cliente da abordagem {access_label} deve estar associado à CPE do cliente.")
        if radio_st and ap and radio_st.access_point_id not in {None, ap.id}:
            raise ValueError(f"O rádio cliente da abordagem {access_label} deve usar o AP selecionado.")
    if scope != "public" and source_block:
        raise ValueError("Somente recursos públicos podem apontar para um bloco publicado no Geofeed.")
    if parent:
        parent_network = _ipam_network(parent.prefix, parent.resource_kind)
        if resource_network.version != parent_network.version or resource_network == parent_network or not resource_network.subnet_of(parent_network):
            raise ValueError("O recurso deve pertencer ao bloco pai selecionado.")
        if parent.scope != scope:
            raise ValueError("A classificação do recurso deve ser compatível com a do bloco pai.")
        if company and parent.company_id and company.id != parent.company_id:
            raise ValueError("O recurso derivado deve usar a mesma empresa do bloco pai.")
        company = parent.company
        minimum_parent_prefix = 24 if resource_network.version == 4 else 32
        if resource_network.prefixlen > minimum_parent_prefix and parent_network.prefixlen < minimum_parent_prefix:
            unit = "/24" if resource_network.version == 4 else "/32"
            raise ValueError(
                f"Um recurso IPv{resource_network.version} menor que {unit} deve ter como pai "
                f"um {unit} ou uma sub-rede menor. O pai selecionado {parent.prefix} é amplo demais."
            )
    requires_parent = resource_kind == "ip" or (resource_network.version == 4 and resource_network.prefixlen > 24) or (resource_network.version == 6 and resource_network.prefixlen > 32)
    if requires_parent and not parent:
        raise ValueError("Este recurso precisa de um bloco pai. Cadastre-o primeiro ou use o botão de cadastro rápido.")
    if not parent and (not company or not company.active):
        raise ValueError("Selecione a empresa proprietária do bloco raiz.")
    latitude = _ipam_coordinate(request.form.get("latitude"), "Latitude", -90, 90)
    longitude = _ipam_coordinate(request.form.get("longitude"), "Longitude", -180, 180)
    if (latitude is None) != (longitude is None):
        raise ValueError("Informe latitude e longitude juntas.")
    return {
        "resource_kind": resource_kind,
        "prefix": prefix,
        "scope": scope,
        "status": status,
        "parent_prefix": parent.prefix if parent else "",
        "parent_id": parent.id if parent else None,
        "company_id": company.id if company else None,
        "geofeed_region": inherited.get("geofeed_region") or _ipam_geofeed_region(source_block, resource_network),
        "allocation_address": _ipam_text(request.form.get("allocation_address"), 255),
        "latitude": latitude,
        "longitude": longitude,
        "vlan": inherited.get("vlan") or _ipam_text(request.form.get("vlan"), 64),
        "vrf": inherited.get("vrf") or _ipam_text(request.form.get("vrf"), 80),
        "description": _ipam_text(request.form.get("description"), 255),
        "notes": _ipam_text(request.form.get("notes"), 4000),
        "source_block_id": source_block.id if source_block else None,
        "customer_id": customer.id if customer else None,
        "pop_id": pop.id if pop else None,
        "router_id": router.id if router else None,
        "cpe_id": cpe.id if cpe else None,
        "access_type": access_type,
        "access_type_2": access_type_2,
        "pop_2_id": pop_2.id if pop_2 else None,
        "router_2_id": router_2.id if router_2 else None,
        "switch_id": switch.id if switch else None,
        "switch_2_id": switch_2.id if switch_2 else None,
        "access_point_id": access_point.id if access_point else None,
        "access_point_2_id": access_point_2.id if access_point_2 else None,
        "st_id": st.id if st else None,
        "st_2_id": st_2.id if st_2 else None,
    }


def _ipam_apply_values(allocation: IpamAllocation, values: dict) -> None:
    for key, value in values.items():
        setattr(allocation, key, value)


def _ipam_approval_snapshot(values: dict) -> dict:
    """Convert validated form values to a JSON-safe review snapshot."""
    snapshot = dict(values)
    for key in ("latitude", "longitude"):
        if snapshot.get(key) is not None:
            snapshot[key] = str(snapshot[key])
    return snapshot


def _pending_ipam_approval(allocation: IpamAllocation) -> IpamApprovalRequest | None:
    return IpamApprovalRequest.query.filter_by(
        allocation_id=allocation.id, status="pending"
    ).order_by(IpamApprovalRequest.created_at.desc()).first()


def _submit_ipam_approval(
    allocation: IpamAllocation,
    values: dict,
    operation: str,
    notes: str,
) -> IpamApprovalRequest:
    if _pending_ipam_approval(allocation):
        raise ValueError("Este recurso já possui uma solicitação de aprovação pendente.")
    if not notes:
        raise ValueError("Informe uma observação para o administrador.")
    allocation.approval_status = "pending"
    change = IpamApprovalRequest(
        allocation=allocation,
        operation=operation,
        status="pending",
        title=f"IPAM: {operation} {allocation.prefix}",
        snapshot_json=canonical_json(_ipam_approval_snapshot(values)),
        notes=notes,
        requested_by_id=current_user().id,
    )
    db.session.add(change)
    db.session.flush()
    admins = User.query.filter(User.active.is_(True)).all()
    admins = [user for user in admins if user.id != current_user().id and user.has_permission("ipam.public.approve")]
    create_in_app_notifications(
        admins,
        f"Aprovação IPAM pendente #{change.id}",
        f"{current_user().email} enviou: {change.title}",
        url_for("panel.ipam_approval_detail", approval_id=change.id),
    )
    send_notification(
        [user.email for user in admins],
        f"[ISP Network Tools] Aprovação IPAM pendente #{change.id}",
        f"{current_user().email} enviou: {change.title}\n\nAcesse o Admin Center para revisar.",
    )
    return change


def _audit_application(log) -> str:
    action = str(getattr(log, "action", "") or "")
    if action.startswith((
        "auth.", "user.", "group.", "setting.", "theme.", "notification.",
        "avatar.", "profile.", "company.", "customer.", "pop_dc.", "service.",
    )):
        return "admin_center"
    if action.startswith(("ipam.", "block.", "entry.", "change.", "publication.", "geofeed.")):
        return "ipam_geofeed"
    if action.startswith(("scan.", "health.", "monitoring.")):
        return "isp_network_health"
    return "admin_center"


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


@bp.get("/internal/health-users")
@limiter.exempt
def internal_health_users():
    """Private directory for Health's delegated scan management."""
    supplied = request.headers.get("X-ISP-Admin-Token", "")
    expected = _admin_scans_token()
    if not expected or not supplied or not hmac.compare_digest(supplied, expected):
        abort(403)
    users = User.query.filter(User.active.is_(True), User.deleted_at.is_(None)).order_by(User.email).all()
    return jsonify({"users": [
        {"subject": str(user.id), "email": user.email,
         "name": user.display_name or user.email, "role": user.role}
        for user in users if user.has_application_access("isp_network_health")
    ]})


def _presence_token(subject: str, email: str) -> str:
    secret = str(current_app.config.get("SSO_SIGNING_SECRET", ""))
    if not secret:
        return ""
    message = f"isp-network-tools:presence:v1:{subject}:{email}".encode("utf-8")
    return hmac.new(secret.encode("utf-8"), message, hashlib.sha256).hexdigest()


@bp.post("/internal/presence")
@csrf.exempt
@limiter.exempt
def internal_presence():
    """Accept a signed activity heartbeat from another suite application."""
    payload = request.get_json(silent=True) or {}
    subject = str(payload.get("subject", "")).strip()
    email = str(payload.get("email", "")).strip().casefold()
    supplied = request.headers.get("X-ISP-Presence-Token", "")
    expected = _presence_token(subject, email)
    if not subject or not email or not expected or not supplied or not hmac.compare_digest(supplied, expected):
        abort(403)
    user = db.session.get(User, int(subject)) if subject.isdigit() else None
    if not user or user.deleted_at is not None or not user.active or user.email.casefold() != email:
        abort(403)
    user.last_seen_at = utcnow()
    db.session.commit()
    return ("", 204)


def _fetch_running_scans(*, include_details: bool = True) -> dict:
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
            params={"details": "1" if include_details else "0"},
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


def _fetch_health_audit_logs(limit: int = 500) -> list[SimpleNamespace]:
    """Read the Health audit stream through its authenticated internal API."""
    base_url = str(current_app.config.get("HEALTH_INTERNAL_BASE_URL", "")).rstrip("/")
    token = _admin_scans_token()
    if not base_url or not token:
        return []
    health_host = urlparse(str(current_app.config.get("HEALTH_BASE_URL", ""))).netloc or "network-health.localhost"
    try:
        response = requests.get(
            f"{base_url}/internal/admin/audit",
            params={"limit": max(1, min(limit, 500))},
            headers={"X-ISP-Admin-Token": token, "Host": health_host},
            timeout=3,
        )
        response.raise_for_status()
        payload = response.json()
    except (requests.RequestException, ValueError):
        current_app.logger.warning("Consulta da auditoria do Network Health indisponível")
        return []
    result = []
    for item in payload.get("logs", []) if isinstance(payload, dict) else []:
        if not isinstance(item, dict):
            continue
        created_at = item.get("created_at")
        try:
            created_at = datetime.fromisoformat(str(created_at).replace("Z", "+00:00"))
        except (TypeError, ValueError):
            continue
        result.append(
            SimpleNamespace(
                created_at=created_at,
                user=SimpleNamespace(email=str(item.get("actor_email") or "Sistema")),
                action=str(item.get("action") or "health.event"),
                entity_type=str(item.get("entity_type") or ""),
                entity_id=str(item.get("entity_id") or ""),
                source_ip=str(item.get("source_ip") or "interno"),
                details=str(item.get("details") or ""),
            )
        )
    return result


def _fetch_recent_health_scans() -> list[dict]:
    user = current_user()
    if not user.has_application_access("isp_network_health"):
        return []
    base_url = str(current_app.config.get("HEALTH_INTERNAL_BASE_URL", "")).rstrip("/")
    token = _admin_scans_token()
    if not base_url or not token:
        return []
    health_host = urlparse(str(current_app.config.get("HEALTH_BASE_URL", ""))).netloc
    try:
        response = requests.get(
            f"{base_url}/internal/admin/recent-scans",
            params={} if user.is_super_admin() else {"subject": str(user.id)},
            headers={"X-ISP-Admin-Token": token, "Host": health_host},
            timeout=3,
        )
        response.raise_for_status()
        payload = response.json()
    except (requests.RequestException, ValueError):
        current_app.logger.warning("Consulta do histórico recente do Network Health indisponível")
        return []
    scans = payload.get("scans", []) if isinstance(payload, dict) else []
    scans = [scan for scan in scans if isinstance(scan, dict)]
    emails = [scan.get("requester_email", "") for scan in scans]
    users = {item.email: item for item in User.query.filter(User.email.in_(emails)).all()} if emails else {}
    for scan in scans:
        actor = users.get(scan.get("requester_email"))
        scan["requester_name"] = (actor.nickname or actor.display_name or actor.email) if actor else scan.get("requester_email", "Usuário")
        scan["scan_url"] = url_for(
            "panel.issue_sso",
            target="isp_network_health",
            scan_id=int(scan["id"]),
        )
    return scans


def _recent_audit(*prefixes: str, limit: int = 8) -> list[AuditLog]:
    filters = [AuditLog.action.startswith(prefix) for prefix in prefixes]
    query = AuditLog.query
    if filters:
        query = query.filter(or_(*filters))
    return query.order_by(AuditLog.created_at.desc()).limit(limit).all()


def _ipam_networks() -> list[tuple[IpamAllocation, ipaddress._BaseNetwork]]:
    result = []
    for allocation in IpamAllocation.query.filter_by(
        scope="public", approval_status="approved"
    ).filter(IpamAllocation.status != "decommissioned").all():
        try:
            result.append((allocation, _ipam_network(allocation.prefix, allocation.resource_kind)))
        except ValueError:
            continue
    return result


def _public_ipam_metrics() -> dict[str, int]:
    records = _ipam_networks()
    all_networks = []
    used_networks = []
    for version in (4, 6):
        all_networks.extend(ipaddress.collapse_addresses([
            network for _item, network in records if network.version == version
        ]))
        used_networks.extend(ipaddress.collapse_addresses([
            network for item, network in records
            if network.version == version and item.status in {"allocated", "reserved", "blocked", "decommissioned"}
        ]))
    total = sum(int(network.num_addresses) for network in all_networks)
    used = sum(int(network.num_addresses) for network in used_networks)
    available = max(0, total - used)
    ipv4_available = sum(
        int(network.num_addresses)
        for network in all_networks
        if network.version == 4
    ) - sum(
        int(network.num_addresses)
        for network in used_networks
        if network.version == 4
    )
    return {
        "available_ips": available,
        "public_ipv4": sum(int(network.num_addresses) for network in all_networks if network.version == 4),
        "public_24s": sum(int(network.num_addresses) for network in all_networks if network.version == 4) // 256,
        "available_ipv4": max(0, ipv4_available),
        "available_24s": max(0, ipv4_available) // 256,
        "public_resources": len(records),
        "public_blocks": sum(1 for item, _network in records if item.resource_kind == "block"),
    }


def _service_values(service: ServiceCatalogItem | None = None) -> dict:
    name = _ipam_text(request.form.get("name"), 180)
    service_type = _ipam_text(request.form.get("service_type"), 80) or "Serviço"
    specification = _ipam_text(request.form.get("specification"), 120)
    description = _ipam_text(request.form.get("description"), 255)
    values = {
        "name": name,
        "service_type": service_type,
        "specification": specification,
        "description": description,
        "active": request.form.get("active") == "on",
    }
    if not name:
        raise ValueError("O nome do serviço é obrigatório.")
    duplicate = ServiceCatalogItem.query.filter(func.lower(ServiceCatalogItem.name) == name.casefold())
    if service:
        duplicate = duplicate.filter(ServiceCatalogItem.id != service.id)
        for key, value in values.items():
            setattr(service, key, value)
    if duplicate.first():
        raise ValueError("Já existe um serviço com este nome.")
    if not service:
        normalized_name = unicodedata.normalize("NFKD", name).encode("ascii", "ignore").decode("ascii")
        values["code"] = re.sub(r"[^a-z0-9]+", "-", normalized_name.casefold()).strip("-")[:80]
        if not values["code"]:
            values["code"] = f"servico-{secrets.token_hex(4)}"
    return values


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
    locations = []
    for allocation in IpamAllocation.query.filter(
        IpamAllocation.latitude.isnot(None),
        IpamAllocation.longitude.isnot(None),
        IpamAllocation.status != "decommissioned",
        IpamAllocation.approval_status == "approved",
    ).order_by(IpamAllocation.prefix).all():
        locations.append({
            "prefix": allocation.prefix,
            "resource_kind": allocation.resource_kind,
            "scope": allocation.scope,
            "address": allocation.allocation_address,
            "latitude": float(allocation.latitude),
            "longitude": float(allocation.longitude),
            "customer": allocation.customer.name if allocation.customer else "",
            "pop": allocation.pop.code if allocation.pop else "",
            "equipment": allocation.equipment.name if allocation.equipment else "",
        })
    return {"macroregions": serialize(macro), "states": serialize(states), "cities": city_items, "locations": locations}


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
    running_scan_data = _fetch_running_scans(include_details=False) if user.is_super_admin() else {"available": True, "scans": []}
    ipam_metrics = _public_ipam_metrics()
    return render_template(
        "dashboard.html",
        company_count=Company.query.filter_by(active=True).count(),
        available_ips=ipam_metrics["public_ipv4"],
        available_24s=ipam_metrics["public_24s"],
        active_customer_count=Customer.query.filter_by(active=True).count(),
        active_service_count=ServiceCatalogItem.query.filter_by(active=True).count(),
        working_hash=snapshot_hash(working),
        latest=latest,
        validation=validation,
        online_user_count=User.query.filter(
            User.active.is_(True), User.deleted_at.is_(None),
            User.last_seen_at >= utcnow() - timedelta(minutes=5)
        ).count(),
        running_scan_count=len(running_scan_data["scans"]),
        map_data=_dashboard_map_data(working),
        recent_health_scans=_fetch_recent_health_scans(),
    )


@bp.get("/api/dashboard/operations")
@login_required
def dashboard_operations():
    user = current_user()
    running = _fetch_running_scans(include_details=False) if user.is_super_admin() else {"available": True, "scans": []}
    return jsonify(
        {
            "online_user_count": len(_online_users()),
            "running_scan_count": len(running.get("scans", [])),
            "running_available": bool(running.get("available")),
            "recent_health_scans": _fetch_recent_health_scans(),
        }
    )


@bp.get("/cadastro")
@login_required
def catalog():
    return render_template("cadastro.html")


@bp.get("/customers")
@login_required
@permission_required("catalog.customers.view")
def customers():
    search = _clean(request.args.get("q"), 120)
    query = Customer.query
    if search:
        query = query.filter(
            or_(
                Customer.name.ilike(f"%{search}%"),
                Customer.cnpj.ilike(f"%{search}%"),
                Customer.contact_email.ilike(f"%{search}%"),
            )
        )
    return render_template(
        "customers.html",
        customers=query.order_by(Customer.active.desc(), Customer.name).all(),
        search=search,
        recent_activity=_recent_audit("customer."),
    )


@bp.get("/pops-dcs")
@login_required
@permission_required("catalog.pops.view")
def pops_dcs():
    search = _clean(request.args.get("q"), 120)
    query = PopDc.query
    if search:
        query = query.filter(
            or_(
                PopDc.name.ilike(f"%{search}%"),
                PopDc.code.ilike(f"%{search}%"),
                PopDc.city.ilike(f"%{search}%"),
            )
        )
    return render_template(
        "pops_dcs.html",
        pops=query.order_by(PopDc.active.desc(), PopDc.name).all(),
        search=search,
        recent_activity=_recent_audit("pop_dc."),
    )


@bp.get("/services")
@login_required
@permission_required("catalog.services.view")
def services():
    search = _clean(request.args.get("q"), 120)
    query = ServiceCatalogItem.query
    if search:
        query = query.filter(or_(
            ServiceCatalogItem.name.ilike(f"%{search}%"),
            ServiceCatalogItem.service_type.ilike(f"%{search}%"),
            ServiceCatalogItem.specification.ilike(f"%{search}%"),
        ))
    return render_template(
        "services.html",
        services=query.order_by(ServiceCatalogItem.active.desc(), ServiceCatalogItem.name).all(),
        search=search,
        recent_activity=_recent_audit("service."),
    )


@bp.route("/services/new", methods=["GET", "POST"])
@permission_required("catalog.services.manage")
def service_new():
    if request.method == "POST":
        try:
            values = _service_values()
            service = ServiceCatalogItem(**values)
            db.session.add(service)
            db.session.flush()
            audit("service.created", "service", service.id, {"name": service.name})
            return _commit_or_flash("Serviço cadastrado no catálogo.", "panel.services")
        except IntegrityError:
            db.session.rollback()
            flash("Já existe um serviço com esse código ou nome.", "error")
        except (ValueError, TypeError) as exc:
            db.session.rollback()
            flash(str(exc), "error")
    return render_template("service_form.html", service=None)


@bp.route("/services/<int:service_id>/edit", methods=["GET", "POST"])
@permission_required("catalog.services.manage")
def service_edit(service_id: int):
    service = db.get_or_404(ServiceCatalogItem, service_id)
    if request.method == "POST":
        try:
            before = {"name": service.name, "active": service.active}
            _service_values(service)
            audit("service.updated", "service", service.id, {"before": before, "after": {"name": service.name, "active": service.active}})
            return _commit_or_flash("Serviço atualizado.", "panel.services")
        except (ValueError, TypeError) as exc:
            db.session.rollback()
            flash(str(exc), "error")
    return render_template("service_form.html", service=service)


@bp.post("/services/<int:service_id>/delete")
@permission_required("catalog.services.manage")
def service_delete(service_id: int):
    service = db.get_or_404(ServiceCatalogItem, service_id)
    service.active = False
    audit("service.deactivated", "service", service.id, {"name": service.name})
    return _commit_or_flash("Serviço desativado. Vínculos existentes foram preservados.", "panel.services")


@bp.get("/ipam")
@application_required("ipam_geofeed")
def ipam():
    try:
        search = _ipam_text(request.args.get("q"), 120)
        requested_classification = _ipam_text(request.args.get("classification") or request.args.get("scope"), 16).lower()
        tab = _ipam_text(request.args.get("tab"), 16).lower() or requested_classification
        tab = tab if tab in {"public", "private"} else "public"
        classification = tab
        resource_kind = _ipam_text(request.args.get("resource_kind"), 16).lower() or "all"
        status = _ipam_text(request.args.get("status"), 24).lower() or "all"
        family = _ipam_text(request.args.get("family"), 4).lower() or "all"
        sort = _ipam_text(request.args.get("sort"), 16).lower() or "largest"
        company_id = _ipam_text(request.args.get("company_id"), 16)
        customer_id = _ipam_text(request.args.get("customer_id"), 16)
        pop_id = _ipam_text(request.args.get("pop_id"), 16)
    except ValueError:
        abort(400)
    query = IpamAllocation.query
    if search:
        query = query.filter(
            or_(
                IpamAllocation.prefix.ilike(f"%{search}%"),
                IpamAllocation.description.ilike(f"%{search}%"),
                IpamAllocation.allocation_address.ilike(f"%{search}%"),
            )
        )
    if classification in {"public", "private", "special"}:
        query = query.filter(IpamAllocation.scope == classification)
    if resource_kind in {"block", "ip"}:
        query = query.filter(IpamAllocation.resource_kind == resource_kind)
    if status in IPAM_STATUSES:
        query = query.filter(IpamAllocation.status == status)
    if family in {"4", "6"}:
        query = query.filter(IpamAllocation.prefix.contains(".") if family == "4" else IpamAllocation.prefix.contains(":"))
    if company_id:
        try:
            query = query.filter(IpamAllocation.company_id == int(company_id))
        except ValueError:
            abort(400)
    if customer_id:
        try:
            query = query.filter(IpamAllocation.customer_id == int(customer_id))
        except ValueError:
            abort(400)
    if pop_id:
        try:
            query = query.filter(IpamAllocation.pop_id == int(pop_id))
        except ValueError:
            abort(400)
    allocations = query.all()
    def allocation_sort_key(item):
        try:
            network = _ipam_network(item.prefix, item.resource_kind)
            return (network.version, network.prefixlen, int(network.network_address), item.prefix)
        except ValueError:
            return (9, 999, 0, item.prefix)
    allocations.sort(key=allocation_sort_key, reverse=sort == "smallest")
    allocation_ids = {allocation.id for allocation in allocations}
    effective_statuses = _ipam_effective_statuses()
    allocation_rows = []
    for allocation in allocations:
        if allocation.parent_id in allocation_ids:
            continue
        try:
            network = _ipam_network(allocation.prefix, allocation.resource_kind)
            has_children = allocation.resource_kind == "block" and (
                (network.version == 4 and network.prefixlen < 32) or bool(allocation.children)
            )
        except ValueError:
            has_children = bool(allocation.children)
        allocation_rows.append({
            "allocation": allocation,
            "depth": 0,
            "has_children": has_children,
            "display_status": effective_statuses.get(allocation.id, allocation.status),
        })
    return render_template(
        "ipam/index.html",
        allocations=allocations,
        allocation_rows=allocation_rows,
        customers=Customer.query.order_by(Customer.active.desc(), Customer.name).all(),
        pops=PopDc.query.order_by(PopDc.active.desc(), PopDc.name).all(),
        equipments=IpamEquipment.query.filter_by(active=True).order_by(IpamEquipment.name).all(),
        companies=Company.query.filter_by(active=True).order_by(Company.name).all(),
        source_blocks=NetworkBlock.query.join(Company).filter(NetworkBlock.active.is_(True), Company.active.is_(True)).order_by(NetworkBlock.cidr).all(),
        parent_blocks=IpamAllocation.query.filter_by(resource_kind="block").filter(
            IpamAllocation.status != "decommissioned",
            IpamAllocation.approval_status == "approved",
        ).order_by(IpamAllocation.prefix).all(),
        statuses=IPAM_STATUSES,
        search=search,
        classification=classification,
        tab=tab,
        resource_kind=resource_kind,
        status=status,
        family=family,
        sort=sort,
        company_id=company_id,
        customer_id=customer_id,
        pop_id=pop_id,
        public_count=IpamAllocation.query.filter_by(scope="public").filter(IpamAllocation.status != "decommissioned").count(),
        private_count=IpamAllocation.query.filter_by(scope="private").filter(IpamAllocation.status != "decommissioned").count(),
        special_count=IpamAllocation.query.filter_by(scope="special").filter(IpamAllocation.status != "decommissioned").count(),
        published_fields=(
            ("ip_prefix", "Prefixo IP"),
            ("alpha2code", "País ISO 3166-1 alpha-2"),
            ("region", "Região ISO 3166-2"),
            ("city", "Cidade"),
            ("postal_code", "Código postal"),
        ),
    )


def _ipam_latest_block(owner: IpamAllocation) -> dict | None:
    snapshot = latest_published_snapshot() or {}
    candidates = {owner.prefix}
    if owner.source_block:
        candidates.add(owner.source_block.cidr)
    canonical = set()
    for value in candidates:
        try:
            canonical.add(str(ipaddress.ip_network(value, strict=True)))
        except ValueError:
            continue
    for block in snapshot.get("blocks", []):
        try:
            cidr = str(ipaddress.ip_network(str(block.get("cidr", "")), strict=True))
        except ValueError:
            continue
        if cidr in canonical:
            return block
    return None


def _ipam_tree_sources(owner: IpamAllocation) -> tuple[list[dict], dict[str, FeedEntry]]:
    published = []
    block = _ipam_latest_block(owner)
    for entry in (block or {}).get("entries", []):
        try:
            network = ipaddress.ip_network(str(entry.get("prefix", "")), strict=True)
        except ValueError:
            continue
        published.append({"network": network, "entry": entry})
    feed_entries = {}
    if owner.source_block_id:
        for entry in FeedEntry.query.filter_by(block_id=owner.source_block_id).all():
            try:
                feed_entries[str(ipaddress.ip_network(entry.prefix, strict=True))] = entry
            except ValueError:
                continue
    return published, feed_entries


def _ipam_owner_and_parent(owner_id: int, parent_prefix: str) -> tuple[IpamAllocation, ipaddress._BaseNetwork, ipaddress._BaseNetwork]:
    owner = db.get_or_404(IpamAllocation, owner_id)
    if owner.resource_kind != "block" or owner.status == "decommissioned":
        abort(404)
    try:
        owner_network = _ipam_network(owner.prefix, owner.resource_kind)
        parent_network = ipaddress.ip_network(parent_prefix, strict=True)
    except ValueError:
        abort(400)
    if parent_network.version != owner_network.version or not parent_network.subnet_of(owner_network):
        abort(400)
    return owner, owner_network, parent_network


def _ipam_nested_allocations(owner: IpamAllocation, owner_network: ipaddress._BaseNetwork) -> list[tuple[IpamAllocation, ipaddress._BaseNetwork]]:
    result = []
    for allocation in IpamAllocation.query.filter(
        IpamAllocation.id != owner.id,
        IpamAllocation.status != "decommissioned",
    ).all():
        try:
            network = _ipam_network(allocation.prefix, allocation.resource_kind)
        except ValueError:
            continue
        if network.version == owner_network.version and network.subnet_of(owner_network):
            result.append((allocation, network))
    return result


def _ipam_tree_nodes(owner: IpamAllocation, owner_network: ipaddress._BaseNetwork, parent_network: ipaddress._BaseNetwork) -> list[dict]:
    published, feed_entries = _ipam_tree_sources(owner)
    allocations = _ipam_nested_allocations(owner, owner_network)
    effective_statuses = _ipam_effective_statuses()
    if parent_network.version == 4 and parent_network.prefixlen < 24:
        networks = list(parent_network.subnets(new_prefix=24))
        return [{
            "prefix": str(network), "display": str(network), "network": network,
            "source": "Faixa calculada", "grouped": False, "allocation": None,
            "feed_entry": None, "has_children": True,
        } for network in networks]

    candidates: dict[str, dict] = {}
    for item in published:
        network = item["network"]
        if network != parent_network and network.subnet_of(parent_network):
            candidates[str(network)] = {
                "prefix": str(network), "display": str(network.network_address) if network.prefixlen == network.max_prefixlen else str(network),
                "network": network, "source": "Último Geofeed publicado", "grouped": network.prefixlen < network.max_prefixlen,
                "allocation": None, "feed_entry": feed_entries.get(str(network)), "has_children": network.prefixlen < network.max_prefixlen,
            }
    for allocation, network in allocations:
        if network != parent_network and network.subnet_of(parent_network):
            candidates[str(network)] = {
                "prefix": str(network), "display": allocation.prefix, "network": network,
                "source": "Cadastro IPAM", "grouped": allocation.resource_kind == "block" and network.prefixlen < network.max_prefixlen,
                "allocation": allocation, "feed_entry": feed_entries.get(str(network)),
                "has_children": allocation.resource_kind == "block" and network.prefixlen < network.max_prefixlen,
                "display_status": effective_statuses.get(allocation.id, allocation.status),
            }

    ordered = sorted(candidates.values(), key=lambda node: (node["network"].prefixlen, int(node["network"].network_address)))
    top_level = []
    for node in ordered:
        if any(node["network"].subnet_of(parent["network"]) for parent in top_level):
            continue
        top_level.append(node)

    if parent_network.version != 4 or parent_network.prefixlen >= 32:
        return top_level
    covered = [node["network"] for node in top_level]
    exact_by_address = {
        int(node["network"].network_address): node
        for node in ordered
        if node["network"].prefixlen == 32
    }
    nodes = list(top_level)
    for address in parent_network:
        if any(ipaddress.ip_network(f"{address}/32").subnet_of(network) for network in covered):
            continue
        exact = exact_by_address.get(int(address))
        if exact:
            nodes.append(exact)
        else:
            nodes.append({
                "prefix": f"{address}/32", "display": str(address), "network": ipaddress.ip_network(f"{address}/32"),
                "source": "Disponível", "grouped": False, "allocation": None,
                "feed_entry": None, "has_children": False,
            })
    return sorted(nodes, key=lambda node: int(node["network"].network_address))


@bp.get("/ipam/tree/children")
@application_required("ipam_geofeed")
def ipam_tree_children():
    try:
        owner_id = int(request.args.get("owner_id", ""))
        parent_prefix = _ipam_text(request.args.get("parent_prefix"), 64)
    except (TypeError, ValueError):
        abort(400)
    owner, owner_network, parent_network = _ipam_owner_and_parent(owner_id, parent_prefix)
    nodes = _ipam_tree_nodes(owner, owner_network, parent_network)
    form_parent = owner
    for allocation, network in _ipam_nested_allocations(owner, owner_network):
        if network == parent_network and allocation.resource_kind == "block":
            form_parent = allocation
            break
    parent_effective, _parent_sources = _ipam_child_inherited_values(form_parent, owner.scope)
    for node in nodes:
        node["effective"], node["effective_sources"] = (
            _ipam_child_inherited_values(node["allocation"], owner.scope)
            if node["allocation"] else ({field: parent_effective[field] for field in IPAM_INHERITED_FIELDS if field in parent_effective}, {})
        )
        node["effective_customer"] = db.session.get(Customer, node["effective"].get("customer_id")) if node["effective"].get("customer_id") else None
        node["effective_pop"] = db.session.get(PopDc, node["effective"].get("pop_id")) if node["effective"].get("pop_id") else None
        node["effective_router"] = db.session.get(IpamEquipment, node["effective"].get("router_id")) if node["effective"].get("router_id") else None
        node["effective_cpe"] = db.session.get(IpamEquipment, node["effective"].get("cpe_id")) if node["effective"].get("cpe_id") else None
    return render_template(
        "ipam/_tree_rows.html", owner=owner, form_parent=form_parent, parent_network=parent_network,
        nodes=nodes, statuses=IPAM_STATUSES,
    )


@bp.get("/ipam/subnet-suggestions")
@application_required("ipam_geofeed")
def ipam_subnet_suggestions():
    try:
        owner_id = int(request.args.get("owner_id", ""))
        parent_prefix = _ipam_text(request.args.get("parent_prefix"), 64)
        prefixlen = int(request.args.get("prefixlen", ""))
    except (TypeError, ValueError):
        abort(400)
    owner, owner_network, parent_network = _ipam_owner_and_parent(owner_id, parent_prefix)
    if parent_network.version != 4 or prefixlen <= parent_network.prefixlen or prefixlen > 32:
        abort(400)
    published, _feed_entries = _ipam_tree_sources(owner)
    existing_networks = [item["network"] for item in published if item["network"] != parent_network and item["network"].subnet_of(parent_network)]
    existing_networks.extend(
        network for _allocation, network in _ipam_nested_allocations(owner, owner_network)
        if network != parent_network and network.subnet_of(parent_network)
    )
    suggestions = []
    for candidate in parent_network.subnets(new_prefix=prefixlen):
        if any(candidate == existing for existing in existing_networks):
            continue
        suggestions.append(str(candidate))
        if len(suggestions) >= 64:
            break
    return jsonify({
        "parent": str(parent_network), "prefixlen": prefixlen,
        "suggestions": suggestions,
        "occupied": sorted({str(network) for network in existing_networks}, key=lambda value: int(ipaddress.ip_network(value).network_address)),
    })


def _geocode_address():
    """Proxy address lookup through the server so browser CSP/CORS do not block it."""
    try:
        query = _ipam_text(request.args.get("q"), 200)
    except ValueError:
        abort(400)
    if len(query) < 3:
        return jsonify({"results": [], "error": "Informe pelo menos 3 caracteres."}), 400

    suite_name = current_app.config.get("SUITE_NAME", "ISP Network Tools")
    service_url = current_app.config.get("ADMIN_BASE_URL") or current_app.config.get("PUBLIC_BASE_URL") or "https://admin-isp.alhambrait.com.br"
    user_agent = f"Mozilla/5.0 (compatible; {suite_name}/1.0; +{service_url})"
    try:
        response = requests.get(
            "https://nominatim.openstreetmap.org/search",
            params={
                "format": "jsonv2",
                "limit": "5",
                "countrycodes": "br",
                "accept-language": "pt-BR",
                "q": query,
            },
            headers={"Accept": "application/json", "User-Agent": user_agent},
            timeout=(3, 8),
        )
        response.raise_for_status()
        payload = response.json()
    except (requests.RequestException, ValueError) as exc:
        current_app.logger.warning("Geocodificação falhou: %s", type(exc).__name__)
        return jsonify({"results": [], "error": "O serviço de localização está indisponível no momento."}), 502

    results = []
    for item in payload if isinstance(payload, list) else []:
        try:
            latitude = float(item["lat"])
            longitude = float(item["lon"])
        except (KeyError, TypeError, ValueError):
            continue
        if not (-90 <= latitude <= 90 and -180 <= longitude <= 180):
            continue
        results.append({
            "lat": latitude,
            "lon": longitude,
            "display_name": _clean(item.get("display_name"), 500),
        })
    return jsonify({"results": results})


@bp.get("/geocode")
@login_required
@limiter.limit("20 per minute")
def geocode_address():
    return _geocode_address()


@bp.get("/ipam/geocode")
@application_required("ipam_geofeed")
@limiter.limit("20 per minute")
def ipam_geocode():
    return _geocode_address()


def _ipam_allocation_form_context(allocation: IpamAllocation | None = None) -> dict:
    prefix_value = allocation.prefix if allocation else (request.form.get("prefix") or request.args.get("prefix") or "")
    source_value = allocation.source_block_id if allocation else (request.form.get("source_block_id") or request.args.get("source_block_id") or "")
    geofeed_preview = None
    if prefix_value and source_value:
        try:
            source_id = int(source_value)
            canonical = str(ipaddress.ip_network(prefix_value, strict=False))
            snapshot = latest_published_snapshot() or {}
            for block in snapshot.get("blocks", []):
                if int(block.get("id", -1)) != source_id:
                    continue
                geofeed_preview = next(
                    (entry for entry in block.get("entries", []) if str(ipaddress.ip_network(str(entry.get("prefix", "")), strict=True)) == canonical),
                    None,
                )
                break
        except (TypeError, ValueError):
            geofeed_preview = None
    parent_value = (request.form.get("parent_id") if request.form else None) or (allocation.parent_id if allocation else request.args.get("parent_id") or "")
    try:
        selected_parent = db.session.get(IpamAllocation, int(parent_value)) if parent_value else None
    except (TypeError, ValueError):
        selected_parent = None
    try:
        preview_network = ipaddress.ip_network(prefix_value, strict=False) if prefix_value else None
    except ValueError:
        preview_network = None
    preview_scope = _classify_ipam_network(preview_network) if preview_network else None
    inherited, inherited_sources = _ipam_child_inherited_values(selected_parent, preview_scope)
    form_values = {}
    for field in IPAM_EFFECTIVE_FIELDS:
        if field in IPAM_INHERITED_FIELDS and field in inherited:
            form_values[field] = inherited[field]
        elif request.form:
            form_values[field] = request.form.get(field, "")
        elif allocation:
            form_values[field] = getattr(allocation, field, None) or ""
        else:
            form_values[field] = ""
    preview_network = preview_network or ipaddress.ip_network("0.0.0.0/0")
    preview_source = db.session.get(NetworkBlock, int(source_value)) if str(source_value).isdigit() else None
    if "geofeed_region" not in inherited:
        form_values["geofeed_region"] = (
            getattr(allocation, "geofeed_region", "") if allocation else ""
        ) or _ipam_geofeed_region(preview_source, preview_network)
    resource_kind_value = request.form.get("resource_kind") or request.args.get("resource_kind") or (allocation.resource_kind if allocation else "block")
    parent_query = IpamAllocation.query.filter_by(resource_kind="block").filter(
        IpamAllocation.id != (allocation.id if allocation else -1),
        IpamAllocation.status != "decommissioned",
        IpamAllocation.approval_status == "approved",
    ).order_by(IpamAllocation.prefix)
    parent_blocks = []
    for candidate in parent_query.all():
        try:
            candidate_network = _ipam_network(candidate.prefix, "block")
            target_network = _ipam_network(
                _ipam_prefix(prefix_value, resource_kind_value) if prefix_value else "0.0.0.0/0",
                resource_kind_value,
            )
        except (TypeError, ValueError):
            parent_blocks = parent_query.all()
            break
        minimum_parent_prefix = 24 if target_network.version == 4 else 32
        if (
            candidate_network.version == target_network.version
            and target_network != candidate_network
            and target_network.subnet_of(candidate_network)
            and (target_network.prefixlen <= minimum_parent_prefix or candidate_network.prefixlen >= minimum_parent_prefix)
        ):
            parent_blocks.append(candidate)
    return {
        "allocation": allocation,
        "prefill": {
            "resource_kind": request.form.get("resource_kind") or request.args.get("resource_kind") or "block",
            "prefix": request.form.get("prefix") or request.args.get("prefix") or "",
            "status": request.form.get("status") or request.args.get("status") or "available",
            "parent_id": request.form.get("parent_id") or request.args.get("parent_id") or "",
            "company_id": request.form.get("company_id") or request.args.get("company_id") or "",
            "source_block_id": request.form.get("source_block_id") or request.args.get("source_block_id") or "",
        },
        "companies": Company.query.filter_by(active=True).order_by(Company.name).all(),
        "customers": Customer.query.filter_by(active=True).order_by(Customer.name).all(),
        "pops": PopDc.query.filter_by(active=True).order_by(PopDc.name).all(),
        "routers": IpamEquipment.query.filter(
            IpamEquipment.active.is_(True), IpamEquipment.equipment_type == "router"
        ).order_by(IpamEquipment.name).all(),
        "switches": IpamEquipment.query.filter(
            IpamEquipment.active.is_(True), IpamEquipment.equipment_type == "switch"
        ).order_by(IpamEquipment.name).all(),
        "cpes": IpamEquipment.query.filter(
            IpamEquipment.active.is_(True), IpamEquipment.equipment_type == "cpe"
        ).order_by(IpamEquipment.name).all(),
        "access_points": IpamEquipment.query.filter(
            IpamEquipment.active.is_(True), IpamEquipment.equipment_type == "radio_ap"
        ).order_by(IpamEquipment.name).all(),
        "radio_sts": IpamEquipment.query.filter(
            IpamEquipment.active.is_(True), IpamEquipment.equipment_type == "radio_st"
        ).order_by(IpamEquipment.name).all(),
        "geofeed_preview": geofeed_preview,
        "inherited": inherited,
        "inherited_sources": inherited_sources,
        "form_values": form_values,
        "parent_contexts": {
            str(parent.id): {
                "values": {
                    field: str(value) if field in {"latitude", "longitude"} else value
                    for field, value in effective_values.items()
                },
                "sources": effective_sources,
            }
            for parent in IpamAllocation.query.filter_by(resource_kind="block")
            .filter(
                IpamAllocation.id != (allocation.id if allocation else -1),
                IpamAllocation.status != "decommissioned",
                IpamAllocation.approval_status == "approved",
            )
            for effective_values, effective_sources in [_ipam_child_inherited_values(parent, preview_scope)]
        },
        "source_blocks": NetworkBlock.query.join(Company).filter(NetworkBlock.active.is_(True), Company.active.is_(True)).order_by(NetworkBlock.cidr).all(),
        "parent_blocks": parent_blocks,
        "statuses": IPAM_STATUSES,
    }


@bp.route("/ipam/equipment/new", methods=["GET", "POST"])
@permission_required("ipam.equipment.manage")
def ipam_equipment_new():
    if request.method == "POST":
        try:
            name = _ipam_text(request.form.get("name"), 160)
            code = _ipam_text(request.form.get("code"), 80).upper()
            if not name or not code:
                raise ValueError("Informe o nome e o código do equipamento.")
            equipment_type = _ipam_text(request.form.get("equipment_type"), 16).lower() or "other"
            if equipment_type not in {"router", "cpe", "switch", "edge_router", "radio_ap", "radio_st"}:
                raise ValueError("Tipo de equipamento inválido.")
            pop_id = _clean(request.form.get("pop_id") or request.args.get("pop_id"), 16)
            secondary_pop_id = _clean(request.form.get("secondary_pop_id") or request.args.get("secondary_pop_id"), 16)
            customer_id = _clean(request.form.get("customer_id") or request.args.get("customer_id"), 16)
            router_id = _clean(request.form.get("router_id") or request.args.get("router_id"), 16)
            secondary_router_id = _clean(request.form.get("secondary_router_id") or request.args.get("secondary_router_id"), 16)
            cpe_id = _clean(request.form.get("cpe_id") or request.args.get("cpe_id"), 16)
            access_point_id = _clean(request.form.get("access_point_id") or request.args.get("access_point_id"), 16)
            pop = db.session.get(PopDc, int(pop_id)) if pop_id else None
            secondary_pop = db.session.get(PopDc, int(secondary_pop_id)) if secondary_pop_id else None
            customer = db.session.get(Customer, int(customer_id)) if customer_id else None
            router = db.session.get(IpamEquipment, int(router_id)) if router_id else None
            secondary_router = db.session.get(IpamEquipment, int(secondary_router_id)) if secondary_router_id else None
            cpe = db.session.get(IpamEquipment, int(cpe_id)) if cpe_id else None
            access_point = db.session.get(IpamEquipment, int(access_point_id)) if access_point_id else None
            if pop_id and (not pop or not pop.active):
                raise ValueError("POP/DC inválido.")
            if secondary_pop_id and (not secondary_pop or not secondary_pop.active):
                raise ValueError("Segundo POP/DC inválido.")
            if pop and secondary_pop and pop.id == secondary_pop.id:
                raise ValueError("As abordagens devem usar POPs/DCs diferentes.")
            if customer_id and (not customer or not customer.active):
                raise ValueError("Cliente inválido.")

            def validate_router(item, label, expected_pop):
                if not item or not item.active or item.equipment_type != "router":
                    raise ValueError(f"{label} inválido.")
                if expected_pop and item.pop_id not in {None, expected_pop.id}:
                    raise ValueError(f"{label} não pertence ao POP/DC selecionado.")

            if equipment_type in {"router", "switch", "edge_router"} and not pop:
                raise ValueError("Selecione o POP/DC onde o equipamento será instalado.")
            if equipment_type == "radio_ap" and (not pop or not customer):
                raise ValueError("Rádio AP exige POP/DC e cliente atendido.")
            if equipment_type == "radio_st" and (not customer or not cpe or not access_point):
                raise ValueError("Rádio cliente (ST) exige cliente, CPE e rádio AP.")
            if equipment_type == "cpe" and not customer:
                raise ValueError("CPE exige um cliente proprietário.")
            if equipment_type == "cpe":
                if pop and not router:
                    raise ValueError("Selecione o Roteador POP da primeira abordagem da CPE.")
                if secondary_pop and not secondary_router:
                    raise ValueError("Selecione o Roteador POP da segunda abordagem da CPE.")
                if router:
                    validate_router(router, "Roteador POP", pop)
                if secondary_router:
                    validate_router(secondary_router, "Segundo Roteador POP", secondary_pop)
                duplicate = IpamEquipment.query.filter_by(
                    equipment_type="cpe", customer_id=customer.id, active=True
                )
                if duplicate.first():
                    raise ValueError("Este cliente já possui uma CPE ativa. Edite a CPE existente para vincular as duas abordagens.")
            if equipment_type == "radio_ap":
                current_count = IpamEquipment.query.filter_by(
                    equipment_type="radio_ap", pop_id=pop.id, active=True
                ).count()
                if current_count >= 100:
                    raise ValueError("Este POP/DC já possui o limite de 100 rádios AP ativos.")
            if equipment_type == "radio_st":
                if cpe.equipment_type != "cpe" or not cpe.active or cpe.customer_id not in {None, customer.id}:
                    raise ValueError("A CPE selecionada não pertence ao cliente informado.")
                if access_point.equipment_type != "radio_ap" or not access_point.active:
                    raise ValueError("Selecione um rádio AP ativo.")
                if access_point.customer_id not in {None, customer.id}:
                    raise ValueError("O rádio AP selecionado atende outro cliente.")
                pop = access_point.pop
                pop_id = str(pop.id) if pop else pop_id

            equipment = IpamEquipment(
                equipment_type=equipment_type,
                name=name,
                code=code,
                pop_id=pop.id if pop else None,
                secondary_pop_id=secondary_pop.id if secondary_pop else None,
                customer_id=customer.id if customer else None,
                router_id=router.id if router else None,
                secondary_router_id=secondary_router.id if secondary_router else None,
                cpe_id=cpe.id if cpe else None,
                access_point_id=access_point.id if access_point else None,
                vendor=_ipam_text(request.form.get("vendor"), 120),
                model=_ipam_text(request.form.get("model"), 120),
                serial_number=_ipam_text(request.form.get("serial_number"), 120),
                location=_ipam_text(request.form.get("location"), 255),
                notes=_ipam_text(request.form.get("notes"), 4000),
                active=True,
            )
            db.session.add(equipment)
            db.session.flush()
            audit("ipam.equipment.created", "equipment", equipment.id, {"name": equipment.name, "code": equipment.code})
            db.session.commit()
            return redirect(url_for("panel.ipam", tab="public", equipment_created=equipment.id, equipment_name=equipment.name))
        except (ValueError, TypeError, IntegrityError) as exc:
            db.session.rollback()
            flash("Já existe um equipamento com esse código." if isinstance(exc, IntegrityError) else str(exc), "error")
    return render_template(
        "ipam/equipment_form.html",
        equipment_type=request.form.get("equipment_type") or request.args.get("equipment_type") or "other",
        result_name=request.args.get("result_name") or "equipment_id",
        pops=PopDc.query.filter_by(active=True).order_by(PopDc.name).all(),
        customers=Customer.query.filter_by(active=True).order_by(Customer.name).all(),
        routers=IpamEquipment.query.filter_by(active=True, equipment_type="router").order_by(IpamEquipment.name).all(),
        cpes=IpamEquipment.query.filter_by(active=True, equipment_type="cpe").order_by(IpamEquipment.name).all(),
        access_points=IpamEquipment.query.filter_by(active=True, equipment_type="radio_ap").order_by(IpamEquipment.name).all(),
    )


@bp.route("/ipam/allocations/new", methods=["GET", "POST"])
@application_required("ipam_geofeed")
@roles_required("admin", "editor")
def ipam_allocation_new():
    if request.method == "POST":
        try:
            allocation = IpamAllocation()
            values = _ipam_allocation_values()
            if values["scope"] == "special":
                raise ValueError("Endereços especiais ou reservados não podem ser cadastrados no IPAM.")
            if values["scope"] == "private" and not current_user().has_permission("ipam.private.manage"):
                abort(403)
            if values["scope"] == "public" and not current_user().has_permission("ipam.public.submit"):
                abort(403)
            _ipam_check_overlap(values)
            _ipam_apply_values(allocation, values)
            db.session.add(allocation)
            db.session.flush()
            if values["scope"] == "public":
                _submit_ipam_approval(allocation, values, "create", values["notes"])
                audit("ipam.allocation.submitted", "allocation", allocation.id, {"prefix": allocation.prefix, "scope": allocation.scope})
                return _commit_or_flash("Recurso público enviado para aprovação.", "panel.ipam")
            allocation.approval_status = "approved"
            audit("ipam.allocation.created", "allocation", allocation.id, {"prefix": allocation.prefix, "scope": allocation.scope})
            return _commit_or_flash("Recurso IPAM cadastrado.", "panel.ipam")
        except IntegrityError:
            db.session.rollback()
            flash("Já existe um recurso IPAM com esse tipo e prefixo.", "error")
        except (ValueError, TypeError) as exc:
            db.session.rollback()
            flash(str(exc), "error")
    return render_template("ipam/allocation_form.html", **_ipam_allocation_form_context())


@bp.route("/ipam/allocations/<int:allocation_id>/edit", methods=["GET", "POST"])
@application_required("ipam_geofeed")
@roles_required("admin", "editor")
def ipam_allocation_edit(allocation_id: int):
    allocation = db.get_or_404(IpamAllocation, allocation_id)
    if request.method == "POST":
        try:
            before = {"prefix": allocation.prefix, "scope": allocation.scope, "status": allocation.status}
            values = _ipam_allocation_values()
            if values["scope"] == "special":
                raise ValueError("Endereços especiais ou reservados não podem ser cadastrados no IPAM.")
            if values["scope"] == "private" and not current_user().has_permission("ipam.private.manage"):
                abort(403)
            if values["scope"] == "public" and not current_user().has_permission("ipam.public.submit"):
                abort(403)
            _ipam_check_overlap(values, allocation.id)
            can_approve_public = current_user().has_permission("ipam.public.approve")
            if allocation.approval_status == "pending" and not can_approve_public:
                raise ValueError("Aguarde a revisão da solicitação pendente antes de editar este recurso.")
            if values["scope"] == "public":
                if can_approve_public:
                    _ipam_apply_values(allocation, values)
                    allocation.approval_status = "approved"
                    for approval in allocation.approval_requests:
                        if approval.status == "pending":
                            approval.status = "approved"
                            approval.reviewed_by_id = current_user().id
                            approval.reviewed_at = utcnow()
                            approval.review_notes = "Aprovado durante a edição por um usuário com permissão de aprovação."
                    audit("ipam.allocation.updated", "allocation", allocation.id, {"before": before, "after": {"prefix": allocation.prefix, "scope": allocation.scope, "status": allocation.status}, "approved_by": current_user().email})
                    return _commit_or_flash("Recurso público atualizado e aprovado.", "panel.ipam")
                _submit_ipam_approval(allocation, values, "update", values["notes"])
                audit("ipam.allocation.update_submitted", "allocation", allocation.id, {"before": before, "prefix": values["prefix"]})
                return _commit_or_flash("Alteração do recurso público enviada para aprovação.", "panel.ipam")
            _ipam_apply_values(allocation, values)
            allocation.approval_status = "approved"
            audit("ipam.allocation.updated", "allocation", allocation.id, {"before": before, "after": {"prefix": allocation.prefix, "scope": allocation.scope, "status": allocation.status}})
            return _commit_or_flash("Recurso IPAM atualizado.", "panel.ipam")
        except IntegrityError:
            db.session.rollback()
            flash("Já existe um recurso IPAM com esse tipo e prefixo.", "error")
        except (ValueError, TypeError) as exc:
            db.session.rollback()
            flash(str(exc), "error")
    return render_template("ipam/allocation_form.html", **_ipam_allocation_form_context(allocation))


@bp.post("/ipam/allocations/<int:allocation_id>/delete")
@application_required("ipam_geofeed")
@roles_required("admin", "editor")
def ipam_allocation_delete(allocation_id: int):
    allocation = db.get_or_404(IpamAllocation, allocation_id)
    if allocation.children:
        flash("Este recurso possui dependências derivadas. Desative ou realoque os filhos antes de desativá-lo.", "error")
        return redirect(url_for("panel.ipam"))
    if allocation.approval_status == "pending":
        flash("Aguarde a revisão da solicitação pendente antes de desativar este recurso.", "error")
        return redirect(url_for("panel.ipam"))
    if allocation.scope == "public":
        if not current_user().has_permission("ipam.public.submit"):
            abort(403)
        values = {
            key: getattr(allocation, key)
            for key in (
                "resource_kind", "prefix", "scope", "status", "parent_prefix", "parent_id",
                "company_id", "allocation_address", "latitude", "longitude", "vlan", "vrf",
                "description", "notes", "source_block_id", "customer_id", "pop_id", "pop_2_id",
                "access_type", "access_type_2", "router_id", "router_2_id", "switch_id", "switch_2_id",
                "cpe_id", "access_point_id", "access_point_2_id", "st_id", "st_2_id",
            )
        }
        values["status"] = "decommissioned"
        try:
            _submit_ipam_approval(allocation, values, "deactivate", _clean(request.form.get("notes"), 4000))
            audit("ipam.allocation.deactivation_submitted", "allocation", allocation.id, {"prefix": allocation.prefix})
            return _commit_or_flash("Desativação do recurso público enviada para aprovação.", "panel.ipam")
        except ValueError as exc:
            db.session.rollback()
            flash(str(exc), "error")
            return redirect(url_for("panel.ipam"))
    if not current_user().has_permission("ipam.private.manage"):
        abort(403)
    allocation.status = "decommissioned"
    audit("ipam.allocation.deactivated", "allocation", allocation.id, {"prefix": allocation.prefix, "scope": allocation.scope})
    return _commit_or_flash("Recurso IPAM desativado. O histórico e os vínculos foram preservados.", "panel.ipam")


@bp.route("/ipam/customers/new", methods=["GET", "POST"])
@bp.route("/customers/new", methods=["GET", "POST"])
@permission_required("catalog.customers.manage")
def ipam_customer_new():
    if request.method == "POST":
        try:
            values = _customer_values()
            services = values.pop("services")
            service_statuses = values.pop("service_statuses")
            customer = Customer(**values)
            customer.services = services
            db.session.add(customer)
            db.session.flush()
            _apply_customer_service_statuses(customer, service_statuses)
            audit("customer.created", "customer", customer.id, {"name": customer.name})
            return _commit_or_flash("Cliente cadastrado no Admin Center.", "panel.customers")
        except IntegrityError:
            db.session.rollback()
            flash("Já existe um cliente com esses dados.", "error")
        except (ValueError, TypeError) as exc:
            db.session.rollback()
            flash(str(exc), "error")
    return render_template("customer_form.html", customer=None, services=ServiceCatalogItem.query.filter_by(active=True).order_by(ServiceCatalogItem.name).all(), service_statuses={})


@bp.route("/ipam/customers/<int:customer_id>/edit", methods=["GET", "POST"])
@bp.route("/customers/<int:customer_id>/edit", methods=["GET", "POST"])
@permission_required("catalog.customers.manage")
def ipam_customer_edit(customer_id: int):
    customer = db.get_or_404(Customer, customer_id)
    if request.method == "POST":
        try:
            before = {"name": customer.name, "cnpj": customer.cnpj, "services": [item.name for item in customer.services]}
            values = _customer_values(customer)
            service_statuses = values.pop("service_statuses")
            values.pop("services", None)
            _apply_customer_service_statuses(customer, service_statuses)
            audit("customer.updated", "customer", customer.id, {"before": before, "after": {"name": customer.name, "cnpj": customer.cnpj, "services": [item.name for item in customer.services]}})
            return _commit_or_flash("Cliente atualizado no Admin Center.", "panel.customers")
        except IntegrityError:
            db.session.rollback()
            flash("Já existe um cliente com esses dados.", "error")
        except (ValueError, TypeError) as exc:
            db.session.rollback()
            flash(str(exc), "error")
    return render_template("customer_form.html", customer=customer, services=ServiceCatalogItem.query.order_by(ServiceCatalogItem.name).all(), service_statuses=_customer_service_statuses(customer))


@bp.post("/ipam/customers/<int:customer_id>/delete")
@bp.post("/customers/<int:customer_id>/delete")
@permission_required("catalog.customers.manage")
def ipam_customer_delete(customer_id: int):
    customer = db.get_or_404(Customer, customer_id)
    customer.active = False
    audit("customer.deactivated", "customer", customer.id, {"name": customer.name})
    return _commit_or_flash("Cliente desativado no Admin Center.", "panel.customers")


@bp.route("/ipam/pops/new", methods=["GET", "POST"])
@bp.route("/pops-dcs/new", methods=["GET", "POST"])
@permission_required("catalog.pops.manage")
def ipam_pop_new():
    if request.method == "POST":
        try:
            values = _pop_dc_values()
            windows = values.pop("access_windows")
            pop = PopDc(**values)
            pop.access_windows = [PopAccessWindow(**window) for window in windows]
            db.session.add(pop)
            db.session.flush()
            audit("pop_dc.created", "pop_dc", pop.id, {"code": pop.code, "name": pop.name})
            result_name = request.args.get("result_name") or request.form.get("result_name")
            if result_name:
                db.session.commit()
                return redirect(url_for("panel.ipam", tab="public", pop_created=pop.id, pop_name=pop.name))
            return _commit_or_flash("POP/DC cadastrado no Admin Center.", "panel.pops_dcs")
        except IntegrityError:
            db.session.rollback()
            flash("Já existe um POP com esse código.", "error")
        except (ValueError, TypeError) as exc:
            db.session.rollback()
            flash(str(exc), "error")
    return render_template(
        "pop_dc_form.html", pop=None, weekdays=WEEKDAYS,
        battery_max_minutes=BATTERY_MAX_MINUTES,
        edge_routers=IpamEquipment.query.filter_by(active=True, equipment_type="edge_router").order_by(IpamEquipment.name).all(),
    )


@bp.route("/ipam/pops/<int:pop_id>/edit", methods=["GET", "POST"])
@bp.route("/pops-dcs/<int:pop_id>/edit", methods=["GET", "POST"])
@permission_required("catalog.pops.manage")
def ipam_pop_edit(pop_id: int):
    pop = db.get_or_404(PopDc, pop_id)
    if request.method == "POST":
        try:
            before = {"code": pop.code, "access_24h": pop.access_24h, "battery_autonomy_minutes": pop.battery_autonomy_minutes}
            _pop_dc_values(pop)
            audit("pop_dc.updated", "pop_dc", pop.id, {"before": before, "after": {"code": pop.code, "access_24h": pop.access_24h, "battery_autonomy_minutes": pop.battery_autonomy_minutes}})
            return _commit_or_flash("POP/DC atualizado no Admin Center.", "panel.pops_dcs")
        except IntegrityError:
            db.session.rollback()
            flash("Já existe um POP com esse código.", "error")
        except (ValueError, TypeError) as exc:
            db.session.rollback()
            flash(str(exc), "error")
    return render_template(
        "pop_dc_form.html", pop=pop, weekdays=WEEKDAYS,
        battery_max_minutes=BATTERY_MAX_MINUTES,
        edge_routers=IpamEquipment.query.filter_by(active=True, equipment_type="edge_router").order_by(IpamEquipment.name).all(),
    )


@bp.post("/ipam/pops/<int:pop_id>/delete")
@bp.post("/pops-dcs/<int:pop_id>/delete")
@permission_required("catalog.pops.manage")
def ipam_pop_delete(pop_id: int):
    pop = db.get_or_404(PopDc, pop_id)
    pop.active = False
    audit("pop_dc.deactivated", "pop_dc", pop.id, {"code": pop.code, "name": pop.name})
    return _commit_or_flash("POP/DC desativado no Admin Center.", "panel.pops_dcs")


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
@permission_required("catalog.companies.view")
def companies():
    search = _clean(request.args.get("q"), 120)
    query = Company.query
    if search:
        query = query.filter(or_(Company.name.ilike(f"%{search}%"), Company.cnpj.ilike(f"%{search}%"), Company.address.ilike(f"%{search}%")))
    return render_template(
        "companies.html", companies=query.order_by(Company.name).all(), search=search
    )


@bp.route("/companies/new", methods=["GET", "POST"])
@permission_required("catalog.companies.manage")
def company_new():
    if request.method == "POST":
        try:
            company = Company(**_company_values())
            db.session.add(company)
            db.session.flush()
            audit("company.created", "company", company.id, {"name": company.name})
            return _commit_or_flash("Empresa cadastrada.", "panel.companies")
        except (ValueError, TypeError, IntegrityError) as exc:
            db.session.rollback()
            flash("Já existe uma empresa com esse CNPJ ou os dados informados são inválidos." if isinstance(exc, IntegrityError) else str(exc), "error")
    return render_template("company_form.html", company=None)


@bp.route("/companies/<int:company_id>/edit", methods=["GET", "POST"])
@permission_required("catalog.companies.manage")
def company_edit(company_id: int):
    company = db.get_or_404(Company, company_id)
    if request.method == "POST":
        try:
            before = {"name": company.name, "cnpj": company.cnpj, "asn": company.default_asn}
            _company_values(company)
            audit(
                "company.updated",
                "company",
                company.id,
                {"before": before, "after": {"name": company.name, "cnpj": company.cnpj, "asn": company.default_asn}},
            )
            return _commit_or_flash("Empresa atualizada.", "panel.companies")
        except (ValueError, TypeError, IntegrityError) as exc:
            db.session.rollback()
            flash("Já existe uma empresa com esse CNPJ ou os dados informados são inválidos." if isinstance(exc, IntegrityError) else str(exc), "error")
    return render_template("company_form.html", company=company)


@bp.route("/companies/<int:company_id>/delete", methods=["GET", "POST"])
@permission_required("catalog.companies.manage")
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
        company.active = False
        audit(
            "company.deactivated",
            "company",
            company.id,
            {"name": company.name, "blocks": [block.cidr for block in blocks], "entries": entries},
            user=current_user(),
        )
        return _commit_or_flash("Empresa desativada. Blocos, histórico e vínculos foram preservados.", "panel.companies")
    return render_template(
        "delete_confirm.html",
        title="Excluir empresa",
        heading=f"Excluir {company.name}?",
        message="A empresa será desativada. Blocos, histórico e auditoria permanecerão preservados.",
        consequences=consequences,
        cancel_endpoint="panel.companies",
        cancel_values={},
    )


@bp.get("/blocks")
@application_required("ipam_geofeed")
@login_required
def blocks():
    # The former Blocks screen is now a compatibility alias.  The unified
    # IPAM inventory is the only place where a block or address is registered.
    return ipam()


@bp.get("/blocks/review")
@application_required("ipam_geofeed")
@roles_required("admin", "editor")
def block_review():
    reviewed = [(block, _block_review(block)) for block in NetworkBlock.query.join(Company).order_by(NetworkBlock.cidr).all()]
    return render_template("block_review.html", reviewed=[item for item in reviewed if item[1]])


@bp.post("/blocks/bulk-update")
@application_required("ipam_geofeed")
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
        if not current_user().has_permission("approvals.review"):
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
@application_required("ipam_geofeed")
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
        if not current_user().has_permission("approvals.review"):
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
@application_required("ipam_geofeed")
@roles_required("admin", "editor")
def block_new():
    if request.method == "GET":
        return redirect(url_for("panel.ipam_allocation_new", resource_kind="block"))
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
            if not current_user().has_permission("approvals.review"):
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
@application_required("ipam_geofeed")
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
            if not current_user().has_permission("approvals.review"):
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
@application_required("ipam_geofeed")
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
@application_required("ipam_geofeed")
@login_required
def block_detail(block_id: int):
    block = db.get_or_404(NetworkBlock, block_id)
    return render_template("block_detail.html", block=block)


@bp.get("/blocks/<int:block_id>/preview.csv")
@application_required("ipam_geofeed")
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
@application_required("ipam_geofeed")
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
@application_required("ipam_geofeed")
@roles_required("admin", "editor")
def block_toggle(block_id: int):
    block = db.get_or_404(NetworkBlock, block_id)
    if not current_user().has_permission("approvals.review"):
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
@application_required("ipam_geofeed")
@roles_required("admin", "editor")
def entry_new(block_id: int):
    block = db.get_or_404(NetworkBlock, block_id)
    if request.method == "POST":
        try:
            if not current_user().has_permission("approvals.review"):
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
@application_required("ipam_geofeed")
@roles_required("admin", "editor")
def entry_edit(entry_id: int):
    entry = db.get_or_404(FeedEntry, entry_id)
    block = entry.block
    if request.method == "POST":
        try:
            _require_change_confirmation()
            before = entry.prefix
            if not current_user().has_permission("approvals.review"):
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
@application_required("ipam_geofeed")
@roles_required("admin", "editor")
def entry_delete(entry_id: int):
    entry = db.get_or_404(FeedEntry, entry_id)
    block_id, prefix = entry.block_id, entry.prefix
    if not current_user().has_permission("approvals.review"):
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
@application_required("ipam_geofeed")
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
@roles_required("super_admin")
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
        sectors=Sector.query.order_by(Sector.active.desc(), Sector.name).all(),
        groups=Group.query.filter_by(active=True).order_by(Group.name).all(),
        users=User.query.filter(User.deleted_at.is_(None)).order_by(User.email).all(),
        permission_options=PERMISSION_OPTIONS)


@bp.get("/access/applications")
@roles_required("super_admin")
def application_access():
    # Kept as a compatibility endpoint for old bookmarks. Application access
    # is now defined by the user's profile, never by grants.
    return redirect(url_for("panel.access"))


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
    next_path = ""
    raw_scan_id = request.args.get("scan_id", "").strip()
    if raw_scan_id:
        if not raw_scan_id.isdigit() or int(raw_scan_id) <= 0:
            abort(400)
        next_path = f"/scans/{int(raw_scan_id)}"
    token = issue_handoff(
        secret,
        subject=str(user.id),
        email=user.email,
        display_name=user.display_name or user.email,
        role=user.role,
        profile=user.role,
        applications=[
            application.code
            for application in Application.query.filter_by(active=True).all()
            if application.public or user.has_application_access(application.code)
        ],
        audience=target,
        next_path=next_path,
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
        return redirect(url_for("panel.access"))
    if Group.query.filter(func.lower(Group.name) == name.casefold()).first():
        flash("Este grupo já está cadastrado.", "error")
        return redirect(url_for("panel.access"))
    group = Group(name=name, description=description, active=True)
    db.session.add(group)
    db.session.flush()
    audit("group.created", "group", group.id, {"name": name}, user=current_user())
    return _commit_or_flash("Grupo criado.", "panel.access")


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
    selected_users = User.query.filter(User.id.in_(user_ids), User.active.is_(True), User.deleted_at.is_(None)).all() if user_ids else []
    conflicts = [
        user.email for user in selected_users
        if any(member_group.id != group.id and member_group.active for member_group in user.groups)
    ]
    if conflicts:
        flash(f"Cada usuário pode pertencer a apenas um grupo. Remova primeiro: {', '.join(conflicts[:4])}.", "error")
        return redirect(url_for("panel.access"))
    group.users = selected_users
    audit("group.members_updated", "group", group.id, {"user_ids": sorted(user_ids)}, user=current_user())
    return _commit_or_flash("Membros do grupo atualizados.", "panel.access")


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
            role = request.form.get("role", "ipam_operator")
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
            if user.role in {"super_admin", "admin", "ipam_operator", "health_operator", "viewer"} and not selected_role.system:
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
@application_required("ipam_geofeed")
@login_required
def changes():
    return render_template(
        "changes.html",
        changes=ChangeRequest.query.order_by(ChangeRequest.created_at.desc()).all(),
        ipam_approvals=IpamApprovalRequest.query.order_by(IpamApprovalRequest.created_at.desc()).all(),
    )


def _require_ipam_approval_view(approval: IpamApprovalRequest) -> None:
    user = current_user()
    if user.id != approval.requested_by_id and not user.has_permission("ipam.public.approve"):
        abort(403)


@bp.get("/ipam/approvals/<int:approval_id>")
@application_required("ipam_geofeed")
@login_required
def ipam_approval_detail(approval_id: int):
    approval = db.get_or_404(IpamApprovalRequest, approval_id)
    _require_ipam_approval_view(approval)
    return render_template(
        "ipam/approval_detail.html",
        approval=approval,
        snapshot=json.loads(approval.snapshot_json),
    )


@bp.post("/ipam/approvals/<int:approval_id>/approve")
@application_required("ipam_geofeed")
@permission_required("ipam.public.approve")
def ipam_approval_approve(approval_id: int):
    approval = db.get_or_404(IpamApprovalRequest, approval_id)
    if approval.status != "pending":
        abort(409)
    if approval.requested_by_id == current_user().id:
        flash("O autor não pode aprovar a própria solicitação.", "error")
        return redirect(url_for("panel.ipam_approval_detail", approval_id=approval.id))
    try:
        snapshot = json.loads(approval.snapshot_json)
        _ipam_check_overlap(snapshot, approval.allocation_id)
        _ipam_apply_values(approval.allocation, snapshot)
        approval.allocation.approval_status = "approved"
        approval.status = "approved"
        approval.reviewed_by_id = current_user().id
        approval.reviewed_at = utcnow()
        approval.review_notes = _clean(request.form.get("review_notes"), 4000)
        audit("ipam.approval.approved", "ipam_approval", approval.id, {"allocation_id": approval.allocation_id})
        db.session.commit()
        create_in_app_notifications(
            [approval.requested_by],
            f"Solicitação IPAM #{approval.id} aprovada",
            f"O recurso {approval.allocation.prefix} foi aprovado.",
            url_for("panel.ipam_approval_detail", approval_id=approval.id),
        )
        flash("Solicitação IPAM aprovada.", "success")
    except (ValueError, TypeError, json.JSONDecodeError) as exc:
        db.session.rollback()
        flash(f"Não foi possível aprovar a solicitação: {exc}", "error")
    return redirect(url_for("panel.ipam_approval_detail", approval_id=approval.id))


@bp.post("/ipam/approvals/<int:approval_id>/reject")
@application_required("ipam_geofeed")
@permission_required("ipam.public.reject")
def ipam_approval_reject(approval_id: int):
    approval = db.get_or_404(IpamApprovalRequest, approval_id)
    if approval.status != "pending":
        abort(409)
    if approval.requested_by_id == current_user().id:
        flash("O autor não pode rejeitar a própria solicitação.", "error")
        return redirect(url_for("panel.ipam_approval_detail", approval_id=approval.id))
    reason = _clean(request.form.get("review_notes"), 4000)
    if not reason:
        flash("Informe o motivo da rejeição.", "error")
        return redirect(url_for("panel.ipam_approval_detail", approval_id=approval.id))
    approval.status = "rejected"
    approval.reviewed_by_id = current_user().id
    approval.reviewed_at = utcnow()
    approval.review_notes = reason
    if approval.operation == "create":
        # Keep the rejected request and its resource as an auditable record;
        # the decommissioned state prevents it from being used or counted.
        approval.allocation.status = "decommissioned"
        approval.allocation.approval_status = "rejected"
    else:
        approval.allocation.approval_status = "approved"
    audit("ipam.approval.rejected", "ipam_approval", approval.id, {"allocation_id": approval.allocation_id})
    db.session.commit()
    create_in_app_notifications(
        [approval.requested_by],
        f"Solicitação IPAM #{approval.id} rejeitada",
        reason,
        url_for("panel.ipam_approval_detail", approval_id=approval.id),
    )
    flash("Solicitação IPAM rejeitada.", "success")
    return redirect(url_for("panel.ipam_approval_detail", approval_id=approval.id))


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
@application_required("ipam_geofeed")
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
@application_required("ipam_geofeed")
@login_required
def change_detail(change_id: int):
    change = db.get_or_404(ChangeRequest, change_id)
    validation = validate_snapshot(json.loads(change.snapshot_json))
    return render_template("change_detail.html", change=change, validation=validation)


@bp.post("/changes/<int:change_id>/approve")
@application_required("ipam_geofeed")
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
@application_required("ipam_geofeed")
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
@application_required("ipam_geofeed")
@login_required
def history():
    return render_template(
        "history.html", publications=Publication.query.order_by(Publication.version.desc()).all()
    )


@bp.get("/history/<int:publication_id>")
@application_required("ipam_geofeed")
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
@application_required("ipam_geofeed")
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
    application = _clean(request.args.get("application"), 64)
    if application not in IPAM_AUDIT_APPLICATIONS:
        application = ""
    query = AuditLog.query.outerjoin(User)
    prefixes = {
        "admin_center": ("auth.", "user.", "group.", "role.", "theme.", "settings.", "profile.", "sector.", "function.", "setup.", "company.", "customer.", "pop_dc.", "service."),
        "ipam_geofeed": ("ipam.", "block.", "entry.", "change.", "publication.", "geofeed."),
        "geofeed_public": ("public.",),
        "isp_network_health": ("scan.", "health.", "monitoring."),
    }
    if application == "isp_network_health":
        query = query.filter(AuditLog.id == -1)
    elif application:
        query = query.filter(or_(*[AuditLog.action.ilike(f"{prefix}%") for prefix in prefixes[application]]))
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
    if not application or application == "isp_network_health":
        health_logs = _fetch_health_audit_logs()
        if search:
            term = search.casefold()
            health_logs = [
                log for log in health_logs
                if term in " ".join(
                    str(getattr(log, field, ""))
                    for field in ("action", "entity_type", "entity_id", "details")
                ).casefold()
                or term in str(getattr(getattr(log, "user", None), "email", "")).casefold()
            ]
        if date_from or date_to:
            try:
                lower = datetime.fromisoformat(date_from) if date_from else None
                upper = datetime.fromisoformat(date_to).replace(hour=23, minute=59, second=59) if date_to else None
                health_logs = [
                    log for log in health_logs
                    if (lower is None or log.created_at.replace(tzinfo=None) >= lower)
                    and (upper is None or log.created_at.replace(tzinfo=None) <= upper)
                ]
            except ValueError:
                pass
        logs = sorted(logs + health_logs, key=lambda log: log.created_at, reverse=True)[:500]
    return render_template(
        "audit.html",
        logs=logs,
        search=search,
        date_from=date_from,
        date_to=date_to,
        application=application,
        application_options=IPAM_AUDIT_APPLICATIONS,
        audit_application=_audit_application,
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
