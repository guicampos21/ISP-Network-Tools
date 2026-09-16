from __future__ import annotations

import hmac
import hashlib
import ipaddress
import json
import secrets
from functools import wraps
from typing import Any, Callable

from flask import Flask, abort, flash, jsonify, redirect, render_template, request, session, url_for
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from redis import Redis
from redis.exceptions import RedisError

from inh.core import detect_target_type
from isp_shared.sso import HandoffError, verify_handoff

from .config import app_config
from .storage import (
    cancel_scan as cancel_stored_scan,
    create_scan,
    get_scan,
    init_schema,
    list_active_scans_for_admin,
    list_results,
    list_scans,
)


app = Flask(__name__, template_folder="templates")
app.config.update(app_config())
if not app.config.get("SECRET_KEY"):
    if app.config.get("APP_ENV") == "production":
        raise RuntimeError("SECRET_KEY não configurada")
    app.config["SECRET_KEY"] = "development-only"
if app.config.get("APP_ENV") == "production" and not app.config.get("SSO_SIGNING_SECRET"):
    raise RuntimeError("SSO_SIGNING_SECRET não configurada")
app.config["TRUSTED_HOSTS"] = app.config.get("TRUSTED_HOSTS", [])
limiter = Limiter(
    key_func=get_remote_address,
    app=app,
    storage_uri=str(app.config["REDIS_URL"]),
    default_limits=["300 per hour"],
)
_schema_ready = False


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
    if kind == "ip" and not _global_ipv4(normalized):
        raise ValueError("O alvo IPv4 precisa ser público e globalmente roteável.")
    if kind == "cidr":
        network = ipaddress.ip_network(normalized, strict=False)
        if network.version != 4 or not network.is_global:
            raise ValueError("O bloco CIDR precisa ser IPv4 público e globalmente roteável.")
    return kind, normalized


def _scan_payload(scan: dict[str, Any]) -> dict[str, Any]:
    result = dict(scan)
    for key in ("created_at", "started_at", "finished_at"):
        if result.get(key) is not None:
            result[key] = result[key].isoformat()
    return result


def _result_payload(result: dict[str, Any]) -> dict[str, Any]:
    payload = dict(result)
    if payload.get("created_at") is not None:
        payload["created_at"] = payload["created_at"].isoformat()
    return payload


def _report_result_groups(results: list[dict[str, Any]]) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Shape raw checks into a compact report view.

    The database keeps one row per DNS query. The browser groups those rows by
    outcome so a large scan opens on its findings and summary instead of an
    unbounded table.
    """
    definitions = [
        ("listed", "Ocorrências encontradas", "listed", "Listagens que exigem análise operacional."),
        ("not_listed", "Sem ocorrência", "clean", "Consultas concluídas sem resposta de listagem."),
        ("whitelisted", "Respostas permitidas", "info", "Respostas classificadas como permitidas pela fonte."),
        ("incomplete", "Consultas incompletas", "warning", "Timeouts e erros que reduzem a confiança do resultado."),
    ]
    buckets = {key: [] for key, *_ in definitions}
    status_labels = {
        "listed": "Listada",
        "not_listed": "Sem ocorrência",
        "whitelisted": "Permitida",
        "timeout": "Timeout",
        "error": "Erro",
    }
    status_tones = {
        "listed": "listed",
        "not_listed": "clean",
        "whitelisted": "info",
        "timeout": "warning",
        "error": "warning",
    }
    for raw_result in results:
        result = dict(raw_result)
        status = str(result.get("status", "")).lower()
        group_key = status if status in {"listed", "not_listed", "whitelisted"} else "incomplete"
        answers = result.get("answers") or []
        result["status_label"] = status_labels.get(status, status or "Indisponível")
        result["status_tone"] = status_tones.get(status, "warning")
        result["answers_text"] = ", ".join(str(answer) for answer in answers) or "—"
        result["query_name"] = str(result.get("query_name", ""))
        result["duration_label"] = f"{int(result.get('duration_ms') or 0)} ms"
        buckets[group_key].append(result)

    groups = []
    for key, title, tone, description in definitions:
        rows = buckets[key]
        if key == "incomplete":
            rows = [*buckets["incomplete"]]
        groups.append(
            {
                "key": key,
                "title": title,
                "tone": tone,
                "description": description,
                "count": len(rows),
                "results": rows,
            }
        )
    featured = [row for row in buckets["listed"][:6]]
    return [group for group in groups if group["count"]], featured


def _report_stats(scan: dict[str, Any], results: list[dict[str, Any]]) -> dict[str, int | str]:
    summary = scan.get("summary_json") if isinstance(scan.get("summary_json"), dict) else {}
    listed_rows = [result for result in results if result.get("status") == "listed"]
    unique_targets = {str(result.get("target_value", "")) for result in results if result.get("target_value")}
    def number(key: str, fallback: int) -> int:
        try:
            return int(summary.get(key, fallback) or 0)
        except (TypeError, ValueError):
            return fallback

    total_checks = number("total_checks", int(scan.get("total_checks") or len(results)))
    completed_checks = int(scan.get("completed_checks") or len(results))
    return {
        "total_checks": total_checks,
        "completed_checks": completed_checks,
        "listed_ips": number("unique_ips_listed", len({str(row.get("target_value")) for row in listed_rows})),
        "clean_ips": number("unique_ips_clean", max(number("unique_ips_scanned", len(unique_targets)) - len({str(row.get("target_value")) for row in listed_rows}), 0)),
        "scanned_ips": number("unique_ips_scanned", len(unique_targets)),
        "blacklists": number("unique_blacklists_hit", len({str(row.get("blacklist")) for row in listed_rows if row.get("blacklist")})),
        "timeouts": number("timeout_results", sum(1 for row in results if row.get("status") == "timeout")),
        "errors": number("error_results", sum(1 for row in results if row.get("status") == "error")),
        "risk_level": str(summary.get("risk_level", "Indisponível")),
    }


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
        scans = []
        for scan in list_active_scans_for_admin():
            payload = _scan_payload(scan)
            payload["results"] = [_result_payload(item) for item in list_results(int(scan["id"]))]
            scans.append(payload)
        return jsonify({"scans": scans})
    except Exception:
        app.logger.exception("Falha ao carregar scans para o Admin Center")
        return jsonify({"error": "Não foi possível consultar os scans ativos."}), 503


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
        "apps": list(payload.get("apps", [])),
    }
    _csrf_token()
    return redirect(url_for("index"))


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
        app_env=app.config["APP_ENV"],
        suite_name=app.config["SUITE_NAME"],
        admin_base_url=app.config["ADMIN_BASE_URL"],
        public_base_url=app.config["PUBLIC_BASE_URL"],
        health_base_url=app.config["HEALTH_BASE_URL"],
        admin_center_url=app.config["ADMIN_BASE_URL"],
        application_links=[
            {"code": "geofeed_public", "name": "Geofeed público", "url": app.config["PUBLIC_BASE_URL"]},
            {"code": "admin_center", "name": "Admin Center", "url": app.config["ADMIN_BASE_URL"]},
            {"code": "isp_network_health", "name": "ISP Network Health", "url": url_for("index")},
        ],
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
    lock_key = f"health:active:{user['sub']}"
    lock_token = secrets.token_urlsafe(24)
    try:
        _ensure_schema()
        client = _redis()
        if not client.set(lock_key, lock_token, nx=True, ex=86400):
            message = "Você já possui uma análise em execução."
            if request.is_json:
                return jsonify({"error": message}), 409
            flash(message, "warning")
            return redirect(url_for("index"))
        scan_id = create_scan(str(user["sub"]), str(user["email"]), normalized, kind, profile)
        client.lpush(
            "health:scan:queue",
            json.dumps({"scan_id": scan_id, "lock_key": lock_key, "lock_token": lock_token}),
        )
    except (RedisError, OSError):
        try:
            _release_lock(client, lock_key, lock_token)
        except Exception:
            pass
        if request.is_json:
            return jsonify({"error": "A fila de análises está indisponível."}), 503
        flash("A fila de análises está indisponível.", "error")
        return redirect(url_for("index"))
    if request.is_json:
        return jsonify({"id": scan_id, "status": "queued"}), 202
    flash(f"Análise #{scan_id} enfileirada.", "success")
    return redirect(url_for("scan_detail", scan_id=scan_id))


@app.get("/scans/<int:scan_id>")
@_protected
def scan_detail(scan_id: int):
    _ensure_schema()
    user = _user()
    scan = get_scan(scan_id, str(user["sub"]))
    if not scan:
        abort(404)
    results = list_results(scan_id) if scan["status"] in {"succeeded", "failed", "canceled"} else []
    result_groups, featured_results = _report_result_groups(results)
    selected_scan = _scan_payload(scan)
    return render_template(
        "index.html",
        scans=[_scan_payload(item) for item in list_scans(str(user["sub"]))],
        selected_scan=selected_scan,
        results=results,
        result_groups=result_groups,
        featured_results=featured_results,
        report_stats=_report_stats(selected_scan, results),
        app_env=app.config["APP_ENV"],
        suite_name=app.config["SUITE_NAME"],
        admin_base_url=app.config["ADMIN_BASE_URL"],
        public_base_url=app.config["PUBLIC_BASE_URL"],
        health_base_url=app.config["HEALTH_BASE_URL"],
        admin_center_url=app.config["ADMIN_BASE_URL"],
        application_links=[
            {"code": "geofeed_public", "name": "Geofeed público", "url": app.config["PUBLIC_BASE_URL"]},
            {"code": "admin_center", "name": "Admin Center", "url": app.config["ADMIN_BASE_URL"]},
            {"code": "isp_network_health", "name": "ISP Network Health", "url": url_for("index")},
        ],
    )


@app.post("/scans/<int:scan_id>/cancel")
@_protected
def cancel_scan(scan_id: int):
    _check_csrf()
    _ensure_schema()
    user = _user()
    if not cancel_stored_scan(scan_id, str(user["sub"])):
        flash("A análise não está mais em execução.", "warning")
    else:
        flash("Cancelamento solicitado.", "success")
    return redirect(url_for("scan_detail", scan_id=scan_id))
