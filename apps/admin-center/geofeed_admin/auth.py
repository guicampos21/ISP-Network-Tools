from __future__ import annotations

from datetime import datetime, timezone
import hmac
import re

from flask import Blueprint, abort, current_app, flash, g, redirect, render_template, request, session, url_for
from werkzeug.security import check_password_hash, generate_password_hash

from . import limiter, oauth
from .avatar import sync_user_avatar
from .models import User, db
from .security import audit, current_user, normalize_email, revoke_remember_token, start_login
from .settings import get_setting
from .two_factor import challenge_required, consume_recovery_code, enable_totp, pending_recovery_codes, qr_matrix, setup_payload, setup_required, store_pending_recovery_codes, verify_code


bp = Blueprint("auth", __name__)


def _strong_password(value: str) -> bool:
    return bool(len(value) >= 12 and re.search(r"[A-Z]", value) and re.search(r"[a-z]", value) and re.search(r"\d", value) and re.search(r"[^A-Za-z0-9]", value))


def _setup_available() -> bool:
    return not User.query.filter_by(role="super_admin", active=True).first()


def _post_login_redirect(user: User):
    """Open every authenticated user at the operational overview."""
    return redirect(url_for("panel.dashboard"))


@bp.route("/setup", methods=["GET", "POST"])
@limiter.limit("5 per hour")
def setup():
    """Create the first local SuperAdmin using a one-time deployment secret."""
    if not _setup_available():
        return redirect(url_for("auth.login"))
    expected_token = str(current_app.config.get("SETUP_TOKEN", ""))
    if not expected_token:
        return render_template(
            "error.html",
            code=503,
            message="O bootstrap inicial não foi habilitado pelo implantador.",
        ), 503
    if request.method == "POST":
        supplied_token = request.form.get("setup_token", "")
        username = request.form.get("username", "").strip().casefold()
        email = normalize_email(request.form.get("email", ""))
        password = request.form.get("password", "")
        try:
            valid_email = email
            if not hmac.compare_digest(supplied_token, expected_token):
                raise ValueError("Token de bootstrap inválido.")
            if not re.fullmatch(r"[a-z0-9][a-z0-9._-]{2,79}", username):
                raise ValueError("Username deve ter de 3 a 80 caracteres, usando letras minúsculas, números, ponto, hífen ou sublinhado.")
            if not valid_email or "@" not in valid_email:
                raise ValueError("Informe um e-mail válido.")
            if not _strong_password(password) or password != request.form.get("password_confirm", ""):
                raise ValueError("A senha deve ter ao menos 12 caracteres, maiúscula, minúscula, número, símbolo e confirmação idêntica.")
            if User.query.filter((User.email == valid_email) | (User.username == username)).first():
                raise ValueError("Já existe uma conta com este e-mail ou username.")
            user = User(
                email=valid_email,
                username=username,
                display_name=request.form.get("display_name", "").strip()[:160] or "SuperAdmin local",
                first_name=request.form.get("first_name", "").strip()[:80],
                last_name=request.form.get("last_name", "").strip()[:80],
                auth_provider="local",
                role="super_admin",
                active=True,
                password_hash=generate_password_hash(password),
                password_change_required=False,
            )
            db.session.add(user)
            db.session.flush()
            audit("setup.super_admin_created", "user", user.id, {"auth_provider": "local"}, user=user)
            db.session.commit()
            flash("SuperAdmin local criado. Entre e configure o autenticador TOTP.", "success")
            return redirect(url_for("auth.login"))
        except ValueError as exc:
            db.session.rollback()
            flash(str(exc), "error")
    return render_template("setup.html")


@bp.get("/login")
def login():
    user = current_user()
    if user:
        return _post_login_redirect(user)
    return render_template(
        "login.html",
        entra_ready=oauth.create_client("entra") is not None and get_setting("auth.m365_enabled", "True") == "True",
        google_ready=oauth.create_client("google") is not None and get_setting("auth.google_enabled", "False") == "True",
        dev_auth=current_app.config.get("DEV_AUTH", False),
        setup_available=_setup_available(),
    )


@bp.get("/auth/login")
@limiter.limit("20 per hour")
def entra_login():
    if get_setting("auth.m365_enabled", "True") != "True":
        abort(404)
    client = oauth.create_client("entra")
    if not client:
        flash("A autenticação Microsoft ainda não foi configurada.", "warning")
        return redirect(url_for("auth.login"))
    session["remember_requested"] = request.args.get("remember") == "1"
    redirect_uri = current_app.config["ADMIN_BASE_URL"] + "/auth/callback"
    return client.authorize_redirect(redirect_uri)


@bp.get("/auth/callback")
@limiter.limit("30 per hour")
def entra_callback():
    client = oauth.create_client("entra")
    if not client:
        abort(503)
    try:
        token = client.authorize_access_token()
        claims = token.get("userinfo") or client.parse_id_token(token)
    except Exception as exc:
        current_app.logger.warning("Falha OIDC: %s", type(exc).__name__)
        audit("auth.failed", details={"reason": "oidc_validation"})
        db.session.commit()
        abort(401)

    tenant_id = str(claims.get("tid", ""))
    object_id = str(claims.get("oid", ""))
    email = normalize_email(
        str(claims.get("email") or claims.get("preferred_username") or "")
    )
    expected_tenant = current_app.config["ENTRA_TENANT_ID"]
    if not object_id or tenant_id != expected_tenant or not email:
        audit("auth.failed", details={"reason": "invalid_identity_claims"})
        db.session.commit()
        abort(401)

    user = User.query.filter_by(entra_oid=object_id, tenant_id=tenant_id).first()
    if not user:
        invited = User.query.filter_by(email=email, entra_oid=None, active=True).first()
        if invited:
            invited.entra_oid = object_id
            invited.tenant_id = tenant_id
            user = invited
            audit("user.identity_bound", "user", user.id, {"email": user.email}, user=user)
    if not user or not user.active:
        audit("auth.denied", details={"reason": "user_not_authorized"})
        db.session.commit()
        abort(403)

    try:
        sync_user_avatar(user.id, str(token.get("access_token", "")))
    except Exception as exc:
        current_app.logger.warning("Falha ao sincronizar foto do usuário: %s", type(exc).__name__)

    user.display_name = str(claims.get("name") or user.display_name or user.email)[:160]
    user.last_login_at = datetime.now(timezone.utc)
    remember = bool(session.get("remember_requested"))
    start_login(user, "m365", remember)
    audit("auth.login", "user", user.id, user=user)
    db.session.commit()
    return _post_login_redirect(user)


@bp.get("/auth/google")
@limiter.limit("20 per hour")
def google_login():
    client = oauth.create_client("google")
    if not client or get_setting("auth.google_enabled", "False") != "True":
        abort(404)
    session["remember_requested"] = request.args.get("remember") == "1"
    return client.authorize_redirect(current_app.config["ADMIN_BASE_URL"] + "/auth/google/callback")


@bp.get("/auth/google/callback")
@limiter.limit("30 per hour")
def google_callback():
    client = oauth.create_client("google")
    if not client:
        abort(503)
    try:
        token = client.authorize_access_token()
        claims = token.get("userinfo") or client.parse_id_token(token)
    except Exception as exc:
        current_app.logger.warning("Falha OIDC Google: %s", type(exc).__name__)
        audit("auth.failed", details={"reason": "google_oidc_validation"})
        db.session.commit()
        abort(401)
    subject = str(claims.get("sub", ""))
    email = normalize_email(str(claims.get("email", "")))
    if not subject or not email or claims.get("email_verified") is False:
        audit("auth.failed", details={"reason": "invalid_google_identity_claims"})
        db.session.commit()
        abort(401)
    user = User.query.filter_by(google_sub=subject, auth_provider="google").first()
    if not user:
        user = User.query.filter_by(email=email, auth_provider="google", google_sub=None, active=True).first()
        if user:
            user.google_sub = subject
    if not user or not user.active:
        audit("auth.denied", details={"reason": "google_user_not_authorized"})
        db.session.commit()
        abort(403)
    user.first_name = str(claims.get("given_name") or user.first_name or "")[:80]
    user.last_name = str(claims.get("family_name") or user.last_name or "")[:80]
    user.display_name = str(claims.get("name") or user.display_name or user.email)[:160]
    user.last_login_at = datetime.now(timezone.utc)
    start_login(user, "google", bool(session.get("remember_requested")))
    audit("auth.login", "user", user.id, {"method": "google"}, user=user)
    db.session.commit()
    return _post_login_redirect(user)


@bp.post("/local-login")
@limiter.limit("10 per 15 minutes")
def local_login():
    if get_setting("auth.local_enabled", str(current_app.config.get("LOCAL_AUTH_ENABLED", True))) != "True":
        abort(404)
    username = request.form.get("username", "").strip().casefold()
    user = User.query.filter_by(username=username, active=True, auth_provider="local").first()
    password = request.form.get("password", "")
    if not user or not user.password_hash or not check_password_hash(user.password_hash, password):
        audit("auth.failed", details={"reason": "local_credentials"})
        db.session.commit()
        flash("Username ou senha inválidos.", "error")
        return redirect(url_for("auth.login"))
    remember = request.form.get("remember") == "on"
    session.clear()
    session["preauth_user_id"] = user.id
    session["auth_method"] = "local"
    session["remember_requested"] = remember
    session.permanent = True
    if setup_required(user):
        return redirect(url_for("auth.two_factor_setup"))
    if challenge_required(user):
        return redirect(url_for("auth.two_factor_verify"))
    return _complete_local_login(user)


def _preauth_user() -> User | None:
    user_id = session.get("preauth_user_id")
    user = db.session.get(User, user_id) if user_id else None
    return user if user and user.active and user.auth_provider == "local" else None


def _complete_local_login(user: User):
    remember = bool(session.get("remember_requested"))
    user.last_login_at = datetime.now(timezone.utc)
    start_login(user, "local", remember)
    audit("auth.login", "user", user.id, {"method": "local"}, user=user)
    db.session.commit()
    if user.password_change_required:
        return redirect(url_for("auth.password_change"))
    return _post_login_redirect(user)


@bp.route("/password/change", methods=["GET", "POST"])
@limiter.limit("10 per 15 minutes")
def password_change():
    user = current_user()
    if not user or user.auth_provider != "local":
        return redirect(url_for("auth.login"))
    if request.method == "POST":
        password = request.form.get("password", "")
        if not _strong_password(password) or password != request.form.get("password_confirm", ""):
            flash("A senha deve ter ao menos 12 caracteres, maiúscula, minúscula, número, símbolo e confirmação idêntica.", "error")
        else:
            user.password_hash = generate_password_hash(password)
            user.password_change_required = False
            audit("user.password_changed", "user", user.id, user=user)
            db.session.commit()
            flash("Senha atualizada.", "success")
            return _post_login_redirect(user)
    return render_template("password_change.html", user=user)


@bp.route("/2fa/setup", methods=["GET", "POST"])
@limiter.limit("10 per 15 minutes")
def two_factor_setup():
    user = _preauth_user()
    if not user:
        return redirect(url_for("auth.login"))
    _secret, uri, recovery_codes = setup_payload(user)
    if request.method == "GET":
        store_pending_recovery_codes(user, recovery_codes)
        # Persist only the encrypted TOTP seed; recovery codes are kept in the
        # pre-authenticated session until the user proves possession of it.
        db.session.commit()
    else:
        recovery_codes = pending_recovery_codes(user) or recovery_codes
    if request.method == "POST":
        code = request.form.get("code", "")
        if not verify_code(user, code):
            flash("Código inválido. Confira o aplicativo autenticador e tente novamente.", "error")
            return render_template("two_factor_setup.html", uri=uri, qr_matrix=qr_matrix(uri), recovery_codes=recovery_codes, user=user)
        enable_totp(user, recovery_codes)
        db.session.commit()
        return _complete_local_login(user)
    return render_template("two_factor_setup.html", uri=uri, qr_matrix=qr_matrix(uri), recovery_codes=recovery_codes, user=user)


@bp.route("/2fa/verify", methods=["GET", "POST"])
@limiter.limit("10 per 15 minutes")
def two_factor_verify():
    user = _preauth_user()
    if not user or not challenge_required(user):
        return redirect(url_for("auth.login"))
    if request.method == "POST":
        code = request.form.get("code", "").strip()
        valid = verify_code(user, code)
        if not valid and request.form.get("use_recovery") == "on":
            valid = consume_recovery_code(user, code)
        if not valid:
            flash("Código 2FA inválido.", "error")
            return render_template("two_factor_verify.html", user=user)
        db.session.commit()
        return _complete_local_login(user)
    return render_template("two_factor_verify.html", user=user)


@bp.post("/logout")
def logout():
    user = current_user()
    if user:
        audit("auth.logout", "user", user.id, user=user)
        db.session.commit()
    revoke_remember_token()
    db.session.commit()
    session.clear()
    return redirect(url_for("auth.login"))


@bp.post("/dev-login")
@limiter.limit("20 per hour")
def dev_login():
    if not current_app.config.get("DEV_AUTH") or current_app.config.get("APP_ENV") != "development":
        abort(404)
    user = User.query.filter_by(active=True).order_by(User.id).first()
    if not user:
        abort(403)
    session.clear()
    session["user_id"] = user.id
    session.permanent = True
    return _post_login_redirect(user)
