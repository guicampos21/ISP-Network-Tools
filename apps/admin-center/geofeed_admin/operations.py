from __future__ import annotations

import hashlib
import ipaddress
import json
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import urlparse

import requests
from flask import current_app

from .geofeed import (
    build_snapshot,
    canonical_json,
    publish_snapshot,
    snapshot_hash,
    validate_geofeed_content,
    validate_snapshot,
)
from .models import (
    ChangeRequest,
    Company,
    FeedEntry,
    HealthCheck,
    NetworkBlock,
    Publication,
    User,
    db,
    utcnow,
)
from .notifications import send_notification
from .security import audit
from .settings import get_setting


def publish(
    snapshot: dict,
    publisher: User,
    summary: str,
    change_request: ChangeRequest | None = None,
) -> Publication:
    validation = validate_snapshot(snapshot)
    if not validation.valid:
        raise ValueError(" ".join(validation.errors))
    archive = publish_snapshot(
        snapshot,
        current_app.config["PUBLIC_ROOT"],
        current_app.config["BACKUP_ROOT"],
        current_app.config["PUBLIC_BASE_URL"],
    )
    latest = Publication.query.order_by(Publication.version.desc()).first()
    publication = Publication(
        version=(latest.version + 1 if latest else 1),
        snapshot_json=canonical_json(snapshot),
        snapshot_hash=snapshot_hash(snapshot),
        summary=summary[:255],
        archive_path=archive,
        published_by_id=publisher.id,
        change_request_id=change_request.id if change_request else None,
    )
    db.session.add(publication)
    if change_request:
        change_request.status = "approved"
        change_request.reviewed_by_id = publisher.id
        change_request.reviewed_at = utcnow()
    audit(
        "publication.created",
        "publication",
        publication.version,
        {"summary": summary, "snapshot_hash": publication.snapshot_hash},
        user=publisher,
    )
    return publication


def replace_working_snapshot(snapshot: dict, user: User) -> None:
    FeedEntry.query.delete()
    NetworkBlock.query.delete()
    Company.query.delete()
    db.session.flush()
    companies: dict[int, Company] = {}
    for item in snapshot.get("companies", []):
        company = Company(
            id=item.get("id"),
            name=item["name"],
            default_asn=item["default_asn"],
            contact_email=item.get("contact_email", ""),
            active=item.get("active", True),
        )
        db.session.add(company)
        companies[item["id"]] = company
    db.session.flush()
    for item in snapshot.get("blocks", []):
        block = NetworkBlock(
            id=item.get("id"),
            cidr=item["cidr"],
            ip_version=item["ip_version"],
            company_id=companies[item["company_id"]].id,
            asn=item["asn"],
            filename=item["filename"],
            description=item.get("description", ""),
            active=item.get("active", True),
        )
        db.session.add(block)
        db.session.flush()
        for entry in item.get("entries", []):
            db.session.add(
                FeedEntry(
                    block_id=block.id,
                    prefix=entry["prefix"],
                    alpha2code=entry.get("alpha2code", ""),
                    region=entry.get("region", ""),
                    city=entry.get("city", ""),
                    postal_code=entry.get("postal_code", ""),
                    sort_order=entry.get("sort_order", 0),
                )
            )
    audit(
        "working.restored",
        "snapshot",
        snapshot_hash(snapshot),
        user=user,
    )


def rdap_check(block: NetworkBlock) -> dict:
    network = ipaddress.ip_network(block.cidr, strict=True)
    url = f"https://rdap.registro.br/ip/{network.network_address}"
    response = requests.get(
        url,
        headers={"Accept": "application/rdap+json", "User-Agent": "ISP-Network-Tools-Admin/1.0"},
        timeout=10,
    )
    response.raise_for_status()
    data = response.json()
    rdap_asn = int(data.get("nicbr_autnum", 0) or 0)
    start = ipaddress.ip_address(data["startAddress"])
    end = ipaddress.ip_address(data["endAddress"])
    authority_ok = start <= network.network_address and end >= network.broadcast_address
    return {
        "ok": authority_ok and rdap_asn == block.asn,
        "authority_ok": authority_ok,
        "expected_asn": block.asn,
        "rdap_asn": rdap_asn,
        "handle": str(data.get("handle", ""))[:128],
        "name": str(data.get("name", ""))[:128],
    }


def _monitoring_int(key: str, default: int, minimum: int, maximum: int) -> int:
    try:
        value = int(get_setting(key, str(default)))
    except (TypeError, ValueError):
        value = default
    return max(minimum, min(maximum, value))


def _monitoring_recipients() -> list[str]:
    configured = get_setting("monitoring.recipients", "")
    recipients = {
        item.strip().casefold()
        for item in configured.replace(";", ",").replace("\n", ",").split(",")
        if item.strip()
    }
    if recipients:
        return sorted(recipients)
    return sorted(
        {
            user.email.casefold()
            for user in User.query.filter(
                User.role.in_(["super_admin", "admin"]),
                User.active.is_(True),
                User.deleted_at.is_(None),
            )
        }
    )


def _aware(value: datetime | None) -> datetime | None:
    if value is None:
        return None
    return value if value.tzinfo else value.replace(tzinfo=timezone.utc)


def periodic_healthcheck_due() -> bool:
    if get_setting("monitoring.periodic_enabled", "False") != "True":
        return False
    interval = _monitoring_int("monitoring.periodic_interval_minutes", 60, 5, 10080)
    latest = HealthCheck.query.order_by(HealthCheck.checked_at.desc()).first()
    return not latest or datetime.now(timezone.utc) - _aware(latest.checked_at) >= timedelta(minutes=interval)


def run_publication_healthchecks() -> tuple[int, int]:
    if get_setting("monitoring.after_publish_enabled", "True") != "True":
        return 0, 0
    return run_healthchecks(trigger="publication")


def run_healthchecks(*, trigger: str = "manual") -> tuple[int, int]:
    publication = Publication.query.order_by(Publication.version.desc()).first()
    if not publication:
        return 0, 0
    snapshot = json.loads(publication.snapshot_json)
    ok_count = 0
    total = 0
    base = current_app.config["PUBLIC_BASE_URL"].rstrip("/")
    internal_base = current_app.config.get("HEALTHCHECK_INTERNAL_BASE_URL", "").rstrip("/")
    public_host = urlparse(base).hostname or ""
    timeout = _monitoring_int("monitoring.timeout_seconds", 12, 3, 60)
    retries = _monitoring_int("monitoring.retries", 1, 0, 5)
    failure_threshold = _monitoring_int("monitoring.failure_threshold", 2, 1, 10)
    repeat_minutes = _monitoring_int("monitoring.repeat_alert_minutes", 240, 5, 10080)
    validate_content = get_setting("monitoring.validate_content", "True") == "True"
    notify_recovery = get_setting("monitoring.notify_recovery", "True") == "True"
    failed_alerts: list[str] = []
    recovered_alerts: list[str] = []
    now = datetime.now(timezone.utc)
    for block in snapshot.get("blocks", []):
        if not block.get("active"):
            continue
        total += 1
        url = f"{base}/{block['filename']}"
        check_url = f"{internal_base}/{block['filename']}" if internal_base else url
        headers = {"User-Agent": "ISP-Network-Tools-Monitor/1.0"}
        if internal_base and public_host:
            headers["Host"] = public_host
        started = time.monotonic()
        response = None
        request_error = None
        for attempt in range(retries + 1):
            try:
                response = requests.get(check_url, headers=headers, timeout=timeout)
                request_error = None
                if response.status_code >= 500 and attempt < retries:
                    continue
                break
            except requests.RequestException as exc:
                request_error = exc
                if attempt < retries:
                    continue
        elapsed = int((time.monotonic() - started) * 1000)
        messages: list[str] = []
        entry_count = None
        if response is None:
            content_hash, ok, status = "", False, None
            messages.append(f"Conexão falhou após {retries + 1} tentativa(s): {type(request_error).__name__}.")
        else:
            status = response.status_code
            content_hash = hashlib.sha256(response.content).hexdigest()
            ok = status == 200
            if not ok:
                messages.append(f"HTTP {status}; esperado 200.")
            content_type = response.headers.get("Content-Type", "").split(";", 1)[0].strip().lower()
            if content_type not in {"application/geofeed+csv", "text/csv"}:
                ok = False
                messages.append(f"Content-Type inesperado: {content_type or 'ausente'}.")
            if validate_content and status == 200:
                validation = validate_geofeed_content(response.content, expected_block=block)
                entry_count = validation.entry_count
                if not validation.valid:
                    ok = False
                    messages.extend(validation.errors[:8])
                messages.extend(f"Aviso: {item}" for item in validation.warnings[:4])
            expected_path = Path(current_app.config["PUBLIC_ROOT"]) / block["filename"]
            if expected_path.is_file():
                expected_hash = hashlib.sha256(expected_path.read_bytes()).hexdigest()
                if content_hash != expected_hash:
                    ok = False
                    messages.append("O conteúdo público não corresponde à última publicação aprovada.")
            else:
                ok = False
                messages.append("A cópia local da última publicação não foi encontrada para comparação.")
        previous = HealthCheck.query.filter_by(target=url).order_by(HealthCheck.checked_at.desc()).first()
        previous_open = bool(previous and previous.incident_open)
        failure_streak = 0 if ok else ((previous.failure_streak if previous else 0) + 1)
        incident_open = previous_open
        last_alert_at = previous.last_alert_at if previous else None
        if ok and previous_open:
            incident_open = False
            if notify_recovery:
                recovered_alerts.append(url)
        elif not ok and failure_streak >= failure_threshold:
            should_alert = not previous_open
            if previous_open and _aware(last_alert_at):
                should_alert = now - _aware(last_alert_at) >= timedelta(minutes=repeat_minutes)
            incident_open = True
            if should_alert:
                failed_alerts.append(f"{url} — {' '.join(messages) or 'Falha não especificada.'}")
                last_alert_at = now
        if ok:
            ok_count += 1
        db.session.add(
            HealthCheck(
                checked_at=now,
                target=url,
                ok=ok,
                http_status=status,
                response_ms=elapsed,
                content_hash=content_hash,
                details=" ".join(messages),
                entry_count=entry_count,
                failure_streak=failure_streak,
                incident_open=incident_open,
                last_alert_at=last_alert_at,
            )
        )
    recipients = _monitoring_recipients()
    if failed_alerts:
        send_notification(
            recipients,
            "[Geofeed] Falha no monitoramento",
            "O monitoramento confirmou falha nos arquivos abaixo:\n\n"
            + "\n".join(failed_alerts)
            + f"\n\nGatilho: {trigger}.",
        )
    if recovered_alerts:
        send_notification(
            recipients,
            "[Geofeed] Monitoramento recuperado",
            "Os arquivos abaixo voltaram a responder corretamente:\n\n"
            + "\n".join(recovered_alerts)
            + f"\n\nGatilho: {trigger}.",
        )
    db.session.commit()
    return ok_count, total


def process_scheduled() -> int:
    now = datetime.now(timezone.utc)
    requests_to_publish = ChangeRequest.query.filter(
        ChangeRequest.status == "scheduled",
        ChangeRequest.scheduled_for.is_not(None),
        ChangeRequest.scheduled_for <= now,
    ).all()
    count = 0
    for change in requests_to_publish:
        reviewer = db.session.get(User, change.reviewed_by_id)
        if not reviewer or not reviewer.active or reviewer.role != "admin":
            change.status = "pending"
            continue
        try:
            snapshot = json.loads(change.snapshot_json)
            replace_working_snapshot(snapshot, reviewer)
            publish(snapshot, reviewer, change.title, change)
            change.status = "approved"
            count += 1
        except Exception as exc:
            current_app.logger.error(
                "Publicação agendada %s falhou: %s", change.id, type(exc).__name__
            )
            change.status = "failed"
            change.review_notes = "Falha técnica durante a publicação agendada."
        db.session.commit()
        if change.status == "approved":
            run_publication_healthchecks()
    return count
