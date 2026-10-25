from __future__ import annotations

import hmac
import hashlib
import ipaddress
import json
import re
import secrets
import time
from datetime import datetime, timezone
from io import BytesIO
from functools import wraps
from typing import Any, Callable
from urllib import request as urllib_request
from urllib.parse import urlparse

from flask import Flask, abort, flash, jsonify, redirect, render_template, request, send_file, session, url_for
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from redis import Redis
from redis.exceptions import RedisError
from werkzeug.middleware.proxy_fix import ProxyFix

from inh.core import detect_target_type, is_dnsbl_test_ipv4
from isp_shared.sso import HandoffError, verify_handoff
from isp_shared.assets import register_suite_assets

from .config import app_config
from .reporting import (
    build_health_pdf, build_report_model, build_summary_block_rows, build_summary_report_model,
    compact_listed_ip_results, pdf_filename, report_target_label, scan_reference,
)
from .storage import (
    cancel_scan as cancel_stored_scan,
    create_scan,
    finish_scan,
    delete_scan as delete_stored_scan,
    get_scan,
    init_schema,
    list_active_scans_for_admin,
    list_all_scans,
    list_audit_logs,
    list_listed_ip_results,
    list_scan_events,
    list_results,
    list_recent_results,
    list_scans,
    list_recent_scans,
    requeue_scan,
    cache_scan_listed_ips,
)


app = Flask(__name__, template_folder="templates")
register_suite_assets(app)
app.config.update(app_config())
if not app.config.get("SECRET_KEY"):
    if app.config.get("APP_ENV") == "production":
        raise RuntimeError("SECRET_KEY não configurada")
    app.config["SECRET_KEY"] = "development-only"
if app.config.get("APP_ENV") == "production" and not app.config.get("SSO_SIGNING_SECRET"):
    raise RuntimeError("SSO_SIGNING_SECRET não configurada")
app.config["TRUSTED_HOSTS"] = app.config.get("TRUSTED_HOSTS", [])
# Nginx Proxy Manager removes /network-health before forwarding the request and
# sends it here as X-Forwarded-Prefix. Trusting this value lets Flask generate
# correct links for SSO, static assets, scan polling and PDF routes.
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_prefix=1)
limiter = Limiter(
    key_func=get_remote_address,
    app=app,
    storage_uri=str(app.config["REDIS_URL"]),
    default_limits=["300 per hour"],
)
_schema_ready = False
_presence_last_sent: dict[str, float] = {}
REPORT_DETAIL_CHECK_LIMIT = 100_000


def _large_report_scan(scan: dict[str, Any]) -> dict[str, Any]:
    summary = scan.get("summary_json") if isinstance(scan.get("summary_json"), dict) else {}
    if "listed_ips" not in summary:
        compact = compact_listed_ip_results(list_listed_ip_results(int(scan["id"])))
        cache_scan_listed_ips(int(scan["id"]), compact)
        summary = {**summary, "listed_ips": compact}
        scan = {**scan, "summary_json": summary}
    return scan


def _large_report_model(scan: dict[str, Any]) -> dict[str, Any]:
    return build_summary_report_model(_scan_payload(_large_report_scan(scan)))


def _ensure_schema() -> None:
    global _schema_ready
    if not _schema_ready:
        init_schema()
        _schema_ready = True


def _redis() -> Redis:
    return Redis.from_url(
        str(app.config["REDIS_URL"]),
        decode_responses=True,
        socket_connect_timeout=2,
        socket_timeout=2,
    )


def _health_directory() -> list[dict[str, str]]:
    token = _admin_scans_token()
    base_url = str(app.config.get("ADMIN_INTERNAL_BASE_URL", "")).rstrip("/")
    if not token or not base_url:
        abort(503)
    host = urlparse(str(app.config.get("ADMIN_BASE_URL", ""))).netloc or "admin-center.localhost"
    directory_request = urllib_request.Request(
        f"{base_url}/internal/health-users",
        headers={"X-ISP-Admin-Token": token, "Host": host},
    )
    try:
        with urllib_request.urlopen(directory_request, timeout=3) as response:
            payload = json.load(response)
    except Exception:
        app.logger.warning("Não foi possível consultar os usuários do Admin Center", exc_info=True)
        abort(503)
    users = payload.get("users", [])
    if not isinstance(users, list):
        abort(503)
    return users


def _superadmin_directory() -> list[dict[str, str]]:
    user = _user() or {}
    if user.get("profile") != "super_admin":
        abort(403)
    directory = _health_directory()
    if not any(str(item.get("subject")) == str(user.get("sub")) and item.get("role") == "super_admin" for item in directory):
        abort(403)
    return directory


def _queue_scan(owner: dict[str, str], target: str, kind: str, profile: str) -> int | None:
    lock_key = f"health:active:{owner['subject']}"
    lock_token = secrets.token_urlsafe(24)
    client = _redis()
    if not client.set(lock_key, lock_token, nx=True, ex=86400):
        return None
    scan_id = None
    try:
        actor = _user() or {}
        scan_id = create_scan(
            owner["subject"], owner["email"], target, kind, profile,
            source_ip=request.remote_addr or "", actor_subject=str(actor.get("sub", "")),
            actor_email=str(actor.get("email", "")),
        )
        client.lpush("health:scan:queue", json.dumps({"scan_id": scan_id, "lock_key": lock_key, "lock_token": lock_token}))
        return scan_id
    except Exception:
        if scan_id is not None:
            finish_scan(scan_id, "failed", error_message="A fila de análises ficou indisponível.")
        _release_lock(client, lock_key, lock_token)
        raise


def _release_lock(client: Redis, key: str, token: str) -> None:
    client.eval(
        "if redis.call('get', KEYS[1]) == ARGV[1] then return redis.call('del', KEYS[1]) else return 0 end",
        1,
        key,
        token,
    )


def _user() -> dict[str, Any] | None:
    value = session.get("health_user")
    return value if isinstance(value, dict) else None


def _presence_signature(subject: str, email: str) -> str:
    secret = str(app.config.get("SSO_SIGNING_SECRET", ""))
    if not secret:
        return ""
    message = f"isp-network-tools:presence:v1:{subject}:{email}".encode("utf-8")
    return hmac.new(secret.encode("utf-8"), message, hashlib.sha256).hexdigest()


def _touch_presence(*, force: bool = False) -> bool:
    user = _user()
    if not user:
        return False
    subject = str(user.get("sub", "")).strip()
    email = str(user.get("email", "")).strip().casefold()
    base_url = str(app.config.get("ADMIN_INTERNAL_BASE_URL", "")).rstrip("/")
    token = _presence_signature(subject, email)
    if not subject or not email or not base_url or not token:
        return False
    now = time.monotonic()
    if not force and now - _presence_last_sent.get(subject, 0.0) < 30:
        return True
    _presence_last_sent[subject] = now
    body = json.dumps({"subject": subject, "email": email}).encode("utf-8")
    admin_host = urlparse(str(app.config.get("ADMIN_BASE_URL", ""))).netloc or "admin-center.localhost"
    internal_request = urllib_request.Request(
        f"{base_url}/internal/presence",
        data=body,
        method="POST",
        headers={
            "Content-Type": "application/json",
            "Content-Length": str(len(body)),
            "X-ISP-Presence-Token": token,
            "Host": admin_host,
        },
    )
    try:
        with urllib_request.urlopen(internal_request, timeout=1.5) as response:
            return 200 <= response.status < 300
    except Exception:
        app.logger.debug("Presença do usuário não pôde ser atualizada no Admin Center", exc_info=True)
        return False


def _application_links() -> list[dict[str, str]]:
    user = _user() or {}
    apps = set(user.get("apps", []))
    links = [
        {"code": "geofeed_public", "name": "Geofeed público", "url": app.config["PUBLIC_BASE_URL"]},
        {"code": "admin_center", "name": "Admin Center", "url": app.config["ADMIN_BASE_URL"]},
        {"code": "isp_network_health", "name": "ISP Network Health", "url": url_for("index")},
    ]
    if "ipam_geofeed" in apps:
        links.insert(
            2,
            {
                "code": "ipam_geofeed",
                "name": "IPAM/Geofeed",
                "url": f"{app.config['ADMIN_BASE_URL'].rstrip('/')}/ipam",
            },
        )
    return sorted(links, key=lambda item: item["name"].casefold())


def _csrf_token() -> str:
    value = session.get("csrf_token")
    if not value:
        value = secrets.token_urlsafe(32)
        session["csrf_token"] = value
    return str(value)


def _check_csrf() -> None:
    supplied = request.form.get("csrf_token", "") or request.headers.get("X-CSRF-Token", "")
    if not supplied or not hmac.compare_digest(supplied, _csrf_token()):
        abort(400)


def _protected(view: Callable):
    @wraps(view)
    def wrapped(*args, **kwargs):
        user = _user()
        if not user:
            return redirect(f"{app.config['ADMIN_BASE_URL']}/login")
        if "isp_network_health" not in user.get("apps", []):
            abort(403)
        _touch_presence()
        return view(*args, **kwargs)

    return wrapped


def _global_ipv4(value: str) -> bool:
    address = ipaddress.ip_address(value)
    return address.version == 4 and address.is_global


def _validate_target(raw_value: str) -> tuple[str, str]:
    value = str(raw_value or "").strip()
    if not value or len(value) > 253 or any(char in value for char in "\r\n\t"):
        raise ValueError("Informe um alvo válido com até 253 caracteres.")
    kind, normalized = detect_target_type(value)
    if kind == "ip" and not (_global_ipv4(normalized) or is_dnsbl_test_ipv4(normalized)):
        raise ValueError(
            "O alvo IPv4 precisa ser público e globalmente roteável, "
            "ou o endereço de teste DNSBL 127.0.0.2."
        )
    if kind == "cidr":
        network = ipaddress.ip_network(normalized, strict=False)
        if network.version != 4 or not network.is_global:
            raise ValueError("O bloco CIDR precisa ser IPv4 público e globalmente roteável.")
    return kind, normalized


def _as_utc(value: Any) -> datetime | None:
    if value is None:
        return None
    if isinstance(value, str):
        try:
            value = datetime.fromisoformat(value)
        except ValueError:
            return None
    if not isinstance(value, datetime):
        return None
    return value if value.tzinfo else value.replace(tzinfo=timezone.utc)


def _duration_label(seconds: float | int | None) -> str:
    total = max(0, int(round(float(seconds or 0))))
    minutes, remaining = divmod(total, 60)
    hours, minutes = divmod(minutes, 60)
    if hours:
        return f"{hours}h {minutes:02d}min"
    if minutes:
        return f"{minutes}min {remaining:02d}s"
    return f"{remaining}s"


def _scan_result_tag(scan: dict[str, Any]) -> tuple[str, str]:
    """Return a concise, user-facing result label for the history list."""
    status = str(scan.get("status", ""))
    if status == "queued":
        return "Aguardando resultado", "pending"
    if status == "running":
        return "Em análise", "running"
    if status == "failed":
        return "Falhou", "failed"
    if status == "canceled":
        return "Cancelada", "canceled"

    summary = scan.get("summary_json")
    if not isinstance(summary, dict):
        return "Concluída", "complete"
    try:
        listed = max(0, int(summary.get("unique_ips_listed") or 0))
    except (TypeError, ValueError):
        listed = 0
    try:
        incomplete = max(0, int(summary.get("timeout_results") or 0))
        incomplete += max(0, int(summary.get("error_results") or 0))
    except (TypeError, ValueError):
        incomplete = 0
    if listed:
        noun = "IP listado" if listed == 1 else "IPs listados"
        return f"{listed} {noun}", "listed"
    if summary.get("listed_results"):
        return "Detecções encontradas", "listed"
    if incomplete:
        return "Resultado incompleto", "incomplete"
    return "Sem detecções", "clean"


def _scan_payload(scan: dict[str, Any]) -> dict[str, Any]:
    result = dict(scan)
    result["reference"] = scan_reference(result)
    result["report_target"] = report_target_label(result)
    status = str(result.get("status", ""))
    total = max(0, int(result.get("total_checks") or 0))
    completed = max(0, min(total or int(result.get("completed_checks") or 0), int(result.get("completed_checks") or 0)))
    started = _as_utc(result.get("started_at"))
    finished = _as_utc(result.get("finished_at"))
    clock = finished or datetime.now(timezone.utc)
    elapsed_seconds = max(0.0, (clock - started).total_seconds()) if started else 0.0
    if status == "succeeded":
        progress_percent = 100
        completed = total or completed
    elif total:
        progress_percent = min(100, max(0, int(round(completed * 100 / total))))
    else:
        progress_percent = 0
    remaining = None
    completed_in_run = max(0, completed - int(result.get("resume_baseline") or 0))
    if status == "running" and completed_in_run > 0 and elapsed_seconds > 0 and total > completed:
        remaining = (total - completed) * (elapsed_seconds / completed_in_run)
    if status == "queued":
        eta_label = "Aguardando o worker"
    elif status == "running" and remaining is None:
        eta_label = "Calculando tempo restante"
    elif status == "running":
        eta_label = f"Restante estimado: {_duration_label(remaining)}"
    else:
        eta_label = "Concluído" if status == "succeeded" else "Indisponível"
    result.update(
        {
            "total_checks": total,
            "completed_checks": completed,
            "profile_label": {"aggressive": "Agressivo", "conservative": "Conservador"}.get(
                str(result.get("profile", "")), str(result.get("profile", ""))
            ),
            "duration_label": (
                _duration_label(elapsed_seconds) if started and (finished or status == "running")
                else "Aguardando" if status == "queued" else "—"
            ),
            "progress_percent": progress_percent,
            "elapsed_seconds": int(round(elapsed_seconds)),
            "elapsed_label": _duration_label(elapsed_seconds),
            "eta_seconds": int(round(remaining)) if remaining is not None else None,
            "eta_label": eta_label,
        }
    )
    result_label, result_slug = _scan_result_tag(result)
    result.update({"result_label": result_label, "result_slug": result_slug})
    for key in ("created_at", "started_at", "finished_at"):
        if result.get(key) is not None:
            result[key] = result[key].isoformat()
    return result


def _event_payload(event: dict[str, Any]) -> dict[str, Any]:
    details = event.get("details") if isinstance(event.get("details"), dict) else {}
    defaults = {
        "queued": "Análise enfileirada.",
        "started": "Worker iniciou a análise.",
        "prepared": "Alvo preparado para consulta.",
        "progress": "Progresso atualizado.",
        "succeeded": "Análise concluída.",
        "failed": "A análise foi encerrada com erro.",
        "canceled": "A análise foi cancelada.",
    }
    created_at = _as_utc(event.get("created_at"))
    return {
        "id": int(event.get("id") or 0),
        "event_type": str(event.get("event_type") or "event"),
        "message": str(details.get("message") or defaults.get(str(event.get("event_type")), "Atividade registrada.")),
        "created_at": created_at.isoformat() if created_at else "",
    }


def _result_payload(result: dict[str, Any]) -> dict[str, Any]:
    payload = dict(result)
    if payload.get("created_at") is not None:
        payload["created_at"] = payload["created_at"].isoformat()
    return payload


def _admin_scans_token() -> str:
    secret = str(app.config.get("SSO_SIGNING_SECRET", ""))
    if not secret:
        return ""
    return hmac.new(
        secret.encode("utf-8"),
        b"isp-network-tools:admin-scans:v1",
        hashlib.sha256,
    ).hexdigest()


@app.before_request
def prepare_request():
    _csrf_token()


@app.context_processor
def inject_template_helpers():
    return {"csrf_token": _csrf_token, "health_user": _user()}


@app.after_request
def security_headers(response):
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; base-uri 'none'; object-src 'none'; "
        "frame-ancestors 'none'; form-action 'self'; style-src 'self'; script-src 'self'"
    )
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=(), payment=(), usb=()"
    response.headers["Cache-Control"] = "no-store"
    if app.config.get("APP_ENV") == "production":
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    return response


@app.get("/internal/health")
@limiter.exempt
def internal_health():
    try:
        _ensure_schema()
        return jsonify({"status": "ok"})
    except Exception:
        return jsonify({"status": "degraded"}), 503


@app.get("/internal/admin/scans")
@limiter.exempt
def internal_admin_scans():
    supplied = request.headers.get("X-ISP-Admin-Token", "")
    expected = _admin_scans_token()
    if not expected or not supplied or not hmac.compare_digest(supplied, expected):
        abort(403)
    try:
        _ensure_schema()
        include_details = request.args.get("details", "1") != "0"
        scans = []
        for scan in list_active_scans_for_admin():
            payload = _scan_payload(scan)
            if include_details:
                payload["results"] = list_recent_results(int(scan["id"]))
            scans.append(payload)
        return jsonify({"scans": scans})
    except Exception:
        app.logger.exception("Falha ao carregar scans para o Admin Center")
        return jsonify({"error": "Não foi possível consultar os scans ativos."}), 503


@app.get("/internal/admin/audit")
@limiter.exempt
def internal_admin_audit():
    supplied = request.headers.get("X-ISP-Admin-Token", "")
    expected = _admin_scans_token()
    if not expected or not supplied or not hmac.compare_digest(supplied, expected):
        abort(403)
    try:
        _ensure_schema()
        limit = int(request.args.get("limit", "500"))
    except ValueError:
        limit = 500
    logs = []
    for log in list_audit_logs(limit):
        details = log.get("details")
        logs.append(
            {
                "created_at": log["created_at"].isoformat(),
                "actor_subject": log.get("actor_subject", ""),
                "actor_email": log.get("actor_email", ""),
                "action": log.get("action", ""),
                "entity_type": log.get("entity_type", ""),
                "entity_id": log.get("entity_id", ""),
                "details": json.dumps(details, ensure_ascii=False, sort_keys=True) if isinstance(details, dict) else str(details or ""),
                "source_ip": log.get("source_ip", ""),
            }
        )
    return jsonify({"logs": logs})


@app.get("/internal/admin/recent-scans")
@limiter.exempt
def internal_recent_scans():
    supplied = request.headers.get("X-ISP-Admin-Token", "")
    expected = _admin_scans_token()
    if not expected or not supplied or not hmac.compare_digest(supplied, expected):
        abort(403)
    _ensure_schema()
    subject = request.args.get("subject")
    return jsonify({"scans": [_scan_payload(scan) for scan in list_recent_scans(subject=subject)]})


@app.get("/sso/callback")
@limiter.limit("30 per hour")
def sso_callback():
    token = request.args.get("token", "")
    try:
        payload = verify_handoff(
            token,
            str(app.config.get("SSO_SIGNING_SECRET", "")),
            audience="isp_network_health",
        )
        if "isp_network_health" not in payload.get("apps", []):
            raise HandoffError("aplicação não autorizada")
        client = _redis()
        key = f"health:sso:{payload['jti']}"
        if not client.set(key, "consumed", nx=True, ex=120):
            raise HandoffError("token já utilizado")
    except (HandoffError, RedisError):
        abort(400)
    session.clear()
    session.permanent = True
    session["health_user"] = {
        "sub": str(payload["sub"]),
        "email": str(payload.get("email", "")),
        "name": str(payload.get("name", "")),
        "role": str(payload.get("role", "")),
        "profile": str(payload.get("profile", payload.get("role", ""))),
        "apps": list(payload.get("apps", [])),
    }
    _csrf_token()
    next_path = str(payload.get("next", ""))
    if not re.fullmatch(r"/scans/[1-9][0-9]*", next_path):
        next_path = ""
    if next_path:
        health_prefix = urlparse(str(app.config.get("HEALTH_BASE_URL", ""))).path.rstrip("/")
        next_path = f"{health_prefix}{next_path}" if health_prefix else next_path
    return redirect(next_path or url_for("index"))


@app.get("/api/presence")
@_protected
def presence():
    _touch_presence(force=True)
    return jsonify({"status": "ok"})


@app.post("/logout")
@_protected
def logout():
    _check_csrf()
    session.clear()
    return redirect(url_for("index"))


@app.get("/")
@_protected
def index():
    _ensure_schema()
    user = _user()
    scans = [_scan_payload(item) for item in list_scans(str(user["sub"]))]
    return render_template(
        "index.html",
        scans=scans,
        selected_scan=None,
        results=[],
        result_groups=[],
        featured_results=[],
        report_stats={},
        report_charts={},
        app_env=app.config["APP_ENV"],
        suite_name=app.config["SUITE_NAME"],
        admin_base_url=app.config["ADMIN_BASE_URL"],
        public_base_url=app.config["PUBLIC_BASE_URL"],
        health_base_url=app.config["HEALTH_BASE_URL"],
        admin_center_url=app.config["ADMIN_BASE_URL"],
        application_links=_application_links(),
        admin_view=False,
    )


@app.get("/users/scans")
@_protected
def user_scans():
    directory = _superadmin_directory()
    _ensure_schema()
    selected_subject = request.args.get("subject", "").strip()
    if selected_subject and not any(item["subject"] == selected_subject for item in directory):
        abort(404)
    try:
        page = max(1, int(request.args.get("page", "1")))
    except ValueError:
        abort(400)
    page = min(page, 100000)
    rows, total = list_all_scans(subject=selected_subject or None, limit=50, offset=(page - 1) * 50)
    return render_template(
        "index.html", scans=[_scan_payload(item) for item in rows], selected_scan=None,
        results=[], result_groups=[], featured_results=[], report_stats={}, report_charts={},
        app_env=app.config["APP_ENV"], suite_name=app.config["SUITE_NAME"],
        admin_base_url=app.config["ADMIN_BASE_URL"], public_base_url=app.config["PUBLIC_BASE_URL"],
        health_base_url=app.config["HEALTH_BASE_URL"], admin_center_url=app.config["ADMIN_BASE_URL"],
        application_links=_application_links(), admin_view=True, users_directory=directory,
        selected_subject=selected_subject, page=page, has_next=page * 50 < total, has_prev=page > 1,
    )


@app.post("/scans")
@_protected
@limiter.limit("20 per hour")
def create_scan_route():
    _check_csrf()
    payload = request.get_json(silent=True) if request.is_json else request.form
    payload = payload or {}
    try:
        kind, normalized = _validate_target(str(payload.get("target", "")))
        profile = str(payload.get("profile", "conservative")).strip().lower()
        if profile not in {"conservative", "aggressive"}:
            raise ValueError("Perfil de análise inválido.")
    except ValueError as exc:
        if request.is_json:
            return jsonify({"error": str(exc)}), 400
        flash(str(exc), "error")
        return redirect(url_for("index"))

    user = _user()
    try:
        _ensure_schema()
        scan_id = _queue_scan({"subject": str(user["sub"]), "email": str(user["email"])}, normalized, kind, profile)
        if scan_id is None:
            message = "Você já possui uma análise em execução."
            if request.is_json:
                return jsonify({"error": message}), 409
            flash(message, "warning")
            return redirect(url_for("index"))
    except (RedisError, OSError):
        if request.is_json:
            return jsonify({"error": "A fila de análises está indisponível."}), 503
        flash("A fila de análises está indisponível.", "error")
        return redirect(url_for("index"))
    if request.is_json:
        return jsonify({"id": scan_id, "status": "queued"}), 202
    flash(f"Análise #{scan_id} enfileirada.", "success")
    return redirect(url_for("scan_detail", scan_id=scan_id))


@app.post("/users/scans")
@_protected
@limiter.limit("20 per hour")
def create_user_scan():
    _check_csrf()
    directory = _superadmin_directory()
    owner = next((item for item in directory if item["subject"] == request.form.get("subject", "")), None)
    if owner is None:
        abort(400)
    try:
        kind, normalized = _validate_target(request.form.get("target", ""))
        profile = request.form.get("profile", "conservative")
        if profile not in {"conservative", "aggressive"}:
            raise ValueError("Perfil de análise inválido.")
    except ValueError as exc:
        flash(str(exc), "error")
        return redirect(url_for("user_scans"))
    _ensure_schema()
    try:
        scan_id = _queue_scan(owner, normalized, kind, profile)
    except (RedisError, OSError):
        flash("A fila de análises está indisponível.", "error")
        return redirect(url_for("user_scans", subject=owner["subject"]))
    if scan_id is None:
        flash("Este usuário já possui uma análise em execução.", "warning")
        return redirect(url_for("user_scans", subject=owner["subject"]))
    flash(f"Análise #{scan_id} iniciada para {owner['email']}.", "success")
    return redirect(url_for("user_scans", subject=owner["subject"]))


@app.get("/scans/<int:scan_id>")
@_protected
def scan_detail(scan_id: int):
    _ensure_schema()
    user = _user()
    scan = get_scan(scan_id, None if user.get("profile") == "super_admin" else str(user["sub"]))
    if not scan:
        abort(404)
    if request.headers.get("X-Requested-With") != "XMLHttpRequest":
        return _render_scan_page(scan_id)
    return _render_scan_page(scan_id)


def _render_scan_page(scan_id: int, *, report_only: bool = False):
    _ensure_schema()
    user = _user()
    scan = get_scan(scan_id, None if user.get("profile") == "super_admin" else str(user["sub"]))
    if not scan:
        abort(404)
    selected_scan = _scan_payload(scan)
    scan_events = [_event_payload(item) for item in list_scan_events(scan_id)]
    if scan["status"] == "succeeded":
        if int(scan.get("total_checks") or 0) > REPORT_DETAIL_CHECK_LIMIT:
            results = []
            report_model = _large_report_model(scan)
        else:
            results = list_results(scan_id)
            report_model = build_report_model(selected_scan, results)
    else:
        results = []
        report_model = {"groups": [], "featured": [], "stats": {}, "charts": {}}
    can_delete_selected_scan = str(scan.get("requester_subject")) == str(user.get("sub"))
    admin_view = not can_delete_selected_scan and user.get("profile") == "super_admin" and not report_only
    return render_template(
        "index.html",
        scans=[_scan_payload(item) for item in (list_all_scans(subject=str(scan["requester_subject"]), limit=50)[0] if admin_view else list_scans(str(user["sub"])))],
        selected_scan=selected_scan,
        scan_events=scan_events,
        results=results,
        result_groups=report_model["groups"],
        featured_results=report_model["featured"],
        report_stats=report_model["stats"],
        report_charts=report_model["charts"],
        app_env=app.config["APP_ENV"],
        suite_name=app.config["SUITE_NAME"],
        admin_base_url=app.config["ADMIN_BASE_URL"],
        public_base_url=app.config["PUBLIC_BASE_URL"],
        health_base_url=app.config["HEALTH_BASE_URL"],
        admin_center_url=app.config["ADMIN_BASE_URL"],
        application_links=_application_links(),
        report_only=report_only,
        can_delete_selected_scan=can_delete_selected_scan,
        admin_view=admin_view,
        users_directory=_superadmin_directory() if admin_view else [],
        selected_subject=str(scan["requester_subject"]) if admin_view else "",
        page=1, has_next=False, has_prev=False,
    )


@app.get("/scans/<int:scan_id>/report")
@_protected
def scan_report_only(scan_id: int):
    _ensure_schema()
    user = _user()
    scan = get_scan(scan_id, None if user.get("profile") == "super_admin" else str(user["sub"]))
    if not scan:
        abort(404)
    return _render_scan_page(scan_id, report_only=True)


@app.get("/api/scans/<int:scan_id>/status")
@_protected
@limiter.limit("120 per minute")
def scan_status(scan_id: int):
    _ensure_schema()
    user = _user()
    scan = get_scan(scan_id, None if user.get("profile") == "super_admin" else str(user["sub"]))
    if not scan:
        abort(404)
    payload = _scan_payload(scan)
    payload["events"] = [_event_payload(item) for item in list_scan_events(scan_id)]
    return jsonify(payload)


@app.get("/scans/<int:scan_id>/report.pdf")
@_protected
@limiter.limit("20 per hour")
def scan_report_pdf(scan_id: int):
    """Generate a self-contained PDF using the report's automatic block rules."""
    _ensure_schema()
    user = _user()
    scan = get_scan(scan_id, None if user.get("profile") == "super_admin" else str(user["sub"]))
    if not scan:
        abort(404)
    if scan["status"] != "succeeded":
        flash("O PDF estará disponível quando a análise terminar.", "warning")
        return redirect(url_for("scan_detail", scan_id=scan_id))
    selected_scan = _scan_payload(scan)
    if int(scan.get("total_checks") or 0) > REPORT_DETAIL_CHECK_LIMIT:
        report = build_health_pdf(selected_scan, model=_large_report_model(scan))
    else:
        report = build_health_pdf(selected_scan, list_results(scan_id))
    return send_file(
        BytesIO(report),
        mimetype="application/pdf",
        as_attachment=True,
        download_name=pdf_filename(scan),
        max_age=0,
    )


@app.get("/api/scans/<int:scan_id>/report-block")
@_protected
@limiter.limit("120 per minute")
def scan_report_block(scan_id: int):
    _ensure_schema()
    user = _user()
    scan = get_scan(scan_id, None if user.get("profile") == "super_admin" else str(user["sub"]))
    if not scan or scan.get("status") != "succeeded":
        abort(404)
    if int(scan.get("total_checks") or 0) <= REPORT_DETAIL_CHECK_LIMIT:
        abort(404)
    report_scan = _large_report_scan(scan)
    try:
        rows = build_summary_block_rows(_scan_payload(report_scan), request.args.get("block", ""))
    except ValueError:
        abort(400)
    return render_template("_report_block_rows.html", rows=rows)


@app.post("/scans/<int:scan_id>/cancel")
@_protected
def cancel_scan(scan_id: int):
    _check_csrf()
    _ensure_schema()
    user = _user()
    scan = get_scan(scan_id)
    if not scan:
        abort(404)
    own = str(scan["requester_subject"]) == str(user["sub"])
    if not own:
        _superadmin_directory()
    if not cancel_stored_scan(
        scan_id, str(user["sub"]) if own else None,
        actor_subject=str(user["sub"]), actor_email=str(user["email"]),
    ):
        flash("A análise não está mais em execução.", "warning")
    else:
        flash("Cancelamento solicitado.", "success")
    return redirect(url_for("scan_detail", scan_id=scan_id) if own else url_for("user_scans", subject=scan["requester_subject"]))


@app.post("/scans/<int:scan_id>/resume")
@_protected
@limiter.limit("20 per hour")
def resume_scan(scan_id: int):
    _check_csrf()
    _ensure_schema()
    user = _user()
    scan = get_scan(scan_id)
    if not scan:
        abort(404)
    own = str(scan["requester_subject"]) == str(user["sub"])
    if not own:
        _superadmin_directory()
    destination = url_for("scan_detail", scan_id=scan_id) if own else url_for("user_scans", subject=scan["requester_subject"])
    if scan["status"] not in {"failed", "canceled"}:
        flash("Somente análises interrompidas podem ser retomadas.", "warning")
        return redirect(destination)
    lock_key = f"health:active:{scan['requester_subject']}"
    lock_token = secrets.token_urlsafe(24)
    try:
        client = _redis()
        if not client.set(lock_key, lock_token, nx=True, ex=86400):
            flash("Este usuário já possui uma análise em execução.", "warning")
            return redirect(destination)
        try:
            resumed = requeue_scan(
                scan_id, str(user["sub"]) if own else None, str(user["sub"]), str(user["email"]),
                request.remote_addr or "",
            )
            if not resumed:
                _release_lock(client, lock_key, lock_token)
                flash("A análise já foi retomada ou não está mais interrompida.", "warning")
                return redirect(destination)
            client.lpush("health:scan:queue", json.dumps({"scan_id": scan_id, "lock_key": lock_key, "lock_token": lock_token}))
        except Exception:
            if get_scan(scan_id)["status"] == "queued":
                finish_scan(scan_id, "failed", error_message="Não foi possível enfileirar a retomada.")
            _release_lock(client, lock_key, lock_token)
            raise
    except (RedisError, OSError):
        flash("A fila de análises está indisponível.", "error")
        return redirect(destination)
    flash(f"Análise #{scan_id} retomada. Consultas já salvas serão ignoradas.", "success")
    return redirect(destination)


@app.post("/scans/<int:scan_id>/delete")
@_protected
def delete_scan(scan_id: int):
    _check_csrf()
    _ensure_schema()
    user = _user()
    if not delete_stored_scan(scan_id, str(user["sub"]), request.remote_addr or ""):
        flash("Somente análises concluídas podem ser excluídas.", "warning")
    else:
        flash(f"Análise #{scan_id} excluída.", "success")
    return redirect(url_for("index"))
