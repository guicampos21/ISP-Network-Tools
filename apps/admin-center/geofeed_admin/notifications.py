from __future__ import annotations

import base64
import smtplib
import re
import socket
from email.message import EmailMessage
from email.utils import formataddr, parseaddr

from flask import current_app
from markupsafe import escape

from .models import InAppNotification, NotificationLog, User, db


def split_sender(value: str | None) -> tuple[str, str]:
    """Split a legacy `Name <address>` sender into independent safe values."""
    name, address = parseaddr(value or "")
    return name.strip(), address.strip()


def format_sender(name: str | None, address: str | None) -> str:
    name = (name or "").replace("\r", " ").replace("\n", " ").strip()
    address = (address or "").replace("\r", "").replace("\n", " ").strip()
    return formataddr((name, address)) if name else address


def _branding() -> tuple[str, str, str]:
    from .settings import get_setting

    company = (get_setting("branding.company_name", current_app.config.get("COMPANY_NAME", "Sua empresa")) or current_app.config.get("COMPANY_NAME", "Sua empresa"))[:120]
    primary = get_setting("branding.primary", "#5619a3")
    secondary = get_setting("branding.secondary", "#7c32c7")
    if not re.fullmatch(r"#[0-9a-fA-F]{6}", primary or ""):
        primary = "#5619a3"
    if not re.fullmatch(r"#[0-9a-fA-F]{6}", secondary or ""):
        secondary = "#7c32c7"
    return company, primary, secondary


def _email_config(overrides: dict | None = None) -> dict:
    from .settings import get_setting

    legacy_from = get_setting("email.from", current_app.config["SMTP_FROM"])
    legacy_name, legacy_address = split_sender(legacy_from)
    from_name = get_setting("email.from_name", legacy_name) or legacy_name
    from_address = get_setting("email.from_address", legacy_address) or legacy_address or legacy_from
    config = {
        "host": get_setting("email.host", current_app.config.get("SMTP_HOST", "")),
        "port": get_setting("email.port", str(current_app.config.get("SMTP_PORT", 587))),
        "security": get_setting(
            "email.security",
            "starttls" if get_setting("email.starttls", str(current_app.config["SMTP_STARTTLS"])) == "True" else "none",
        ),
        "auth_method": get_setting("email.auth_method", "password"),
        "username": get_setting("email.username", current_app.config.get("SMTP_USERNAME", "")),
        "password": get_setting("email.password", current_app.config.get("SMTP_PASSWORD", "")),
        "timeout": get_setting("email.timeout", "15"),
        "from_name": from_name,
        "from_address": from_address,
        "from": format_sender(from_name, from_address),
        "reply_to": get_setting("email.reply_to", ""),
        "support_address": get_setting("email.support_address", from_address),
    }
    if overrides:
        config.update({key: value for key, value in overrides.items() if value is not None})
    return config


def _smtp_authenticate(smtp: smtplib.SMTP, config: dict) -> None:
    auth_method = config.get("auth_method", "password")
    if auth_method == "none":
        return
    username = str(config.get("username") or "")
    password = str(config.get("password") or "")
    if not username or not password:
        raise ValueError("Informe usuário e senha/token para autenticar no servidor.")
    if auth_method == "oauth2":
        payload = f"user={username}\x01auth=Bearer {password}\x01\x01".encode("utf-8")
        code, message = smtp.docmd("AUTH", "XOAUTH2 " + base64.b64encode(payload).decode("ascii"))
        if code != 235:
            raise smtplib.SMTPAuthenticationError(code, message)
        return
    smtp.login(username, password)


def _smtp_session(config: dict):
    host = str(config.get("host") or "").strip()
    if not host:
        raise ValueError("Servidor SMTP não informado.")
    try:
        port = int(config.get("port") or 587)
        timeout = int(config.get("timeout") or 15)
    except (TypeError, ValueError) as exc:
        raise ValueError("Porta e timeout devem ser números inteiros.") from exc
    if not 1 <= port <= 65535:
        raise ValueError("A porta deve estar entre 1 e 65535.")
    if not 3 <= timeout <= 60:
        raise ValueError("O timeout deve estar entre 3 e 60 segundos.")
    security = config.get("security", "starttls")
    if security == "ssl":
        smtp = smtplib.SMTP_SSL(host, port, timeout=timeout)
    else:
        smtp = smtplib.SMTP(host, port, timeout=timeout)
        if security == "starttls":
            smtp.starttls()
    _smtp_authenticate(smtp, config)
    return smtp


def test_smtp_connection(overrides: dict | None = None) -> tuple[bool, str]:
    """Check reachability, encryption and optional authentication without sending mail."""
    config = _email_config(overrides)
    smtp = None
    try:
        smtp = _smtp_session(config)
        return True, "Servidor acessível e autenticação concluída."
    except ValueError as exc:
        return False, str(exc)
    except smtplib.SMTPAuthenticationError as exc:
        return False, _safe_smtp_failure(exc)
    except (smtplib.SMTPException, socket.timeout, OSError) as exc:
        return False, _safe_smtp_failure(exc)
    finally:
        if smtp is not None:
            try:
                smtp.quit()
            except (smtplib.SMTPException, OSError):
                smtp.close()


def _safe_smtp_failure(exc: Exception) -> str:
    """Return a useful diagnostic without exposing addresses, tokens or credentials."""
    if isinstance(exc, smtplib.SMTPAuthenticationError):
        return f"Autenticação rejeitada pelo servidor SMTP (código {exc.smtp_code})."
    if isinstance(exc, smtplib.SMTPRecipientsRefused):
        return "O servidor recusou o destinatário do e-mail. Verifique o endereço e as regras de relay."
    if isinstance(exc, smtplib.SMTPSenderRefused):
        return f"O servidor recusou o remetente (código {exc.smtp_code}). Verifique se o remetente está autorizado."
    if isinstance(exc, smtplib.SMTPDataError):
        return f"O servidor recusou o conteúdo da mensagem (código {exc.smtp_code})."
    if isinstance(exc, smtplib.SMTPResponseException):
        return f"O servidor SMTP recusou a operação (código {exc.smtp_code})."
    if isinstance(exc, (socket.timeout, TimeoutError)):
        return "O servidor não respondeu dentro do timeout configurado."
    if isinstance(exc, socket.gaierror):
        return "Não foi possível resolver o nome do servidor SMTP (DNS)."
    if isinstance(exc, ConnectionRefusedError):
        return "A conexão foi recusada pelo servidor SMTP ou pela rede."
    if isinstance(exc, (OSError, smtplib.SMTPConnectError, smtplib.SMTPServerDisconnected)):
        return "A conexão com o servidor foi interrompida antes do envio."
    if isinstance(exc, ValueError):
        return str(exc)
    return f"Falha SMTP ({type(exc).__name__}). Verifique os parâmetros e os logs do servidor."


def send_notification(
    recipients: list[str],
    subject: str,
    body: str,
    html_body: str | None = None,
    smtp_config: dict | None = None,
) -> tuple[str, str]:
    recipients = sorted({item.strip().casefold() for item in recipients if item.strip()})
    if not recipients:
        return "skipped", "Nenhum destinatário informado."
    from .settings import get_setting
    config = _email_config(smtp_config)
    host = config["host"]
    if not host:
        for recipient in recipients:
            db.session.add(
                NotificationLog(
                    recipient=recipient,
                    subject=subject[:255],
                    status="skipped",
                    details="SMTP não configurado",
                )
            )
        return "skipped", "SMTP não configurado."

    message = EmailMessage()
    message["From"] = format_sender(config.get("from_name"), config.get("from_address")) or config["from"]
    if config.get("reply_to"):
        message["Reply-To"] = config["reply_to"]
    message["To"] = ", ".join(recipients)
    message["Subject"] = subject
    message.set_content(body)
    if html_body:
        message.add_alternative(html_body, subtype="html")
    try:
        with _smtp_session(config) as smtp:
            refused = smtp.send_message(message)
        if refused:
            codes = sorted({str(result[0]) for result in refused.values() if result})
            code_suffix = f" (código(s) {', '.join(codes)})" if codes else ""
            status, details = "failed", f"O servidor recusou um ou mais destinatários{code_suffix}."
        else:
            status, details = "sent", ""
    except Exception as exc:  # O detalhe permanece no banco administrativo.
        current_app.logger.warning("Falha ao enviar notificação: %s", type(exc).__name__)
        status, details = "failed", _safe_smtp_failure(exc)
    for recipient in recipients:
        db.session.add(
            NotificationLog(
                recipient=recipient,
                subject=subject[:255],
                status=status,
                details=details,
            )
        )
    if status == "sent":
        return status, "O servidor SMTP aceitou a mensagem para processamento."
    return status, details


def admin_emails() -> list[str]:
    return [
        user.email
        for user in User.query.filter_by(role="admin", active=True).order_by(User.email)
    ]


def send_welcome_email(user: User, temporary_password: str | None = None) -> None:
    """Send the branded onboarding model without persisting the password."""
    from .settings import get_setting

    portal = current_app.config.get("ADMIN_BASE_URL", "")
    suite = current_app.config.get("SUITE_NAME", "ISP Network Tools")
    company, primary, secondary = _branding()
    name = user.display_name or user.first_name or user.username or user.email
    provider_label = {
        "m365": "Microsoft 365",
        "google": "Google Workspace",
        "local": "Login local",
    }.get(user.auth_provider, "Login do portal")
    if user.auth_provider != "local":
        temporary_password = None
    support_address = get_setting("email.support_address", "") or get_setting("email.reply_to", "")
    if not support_address:
        support_address = _email_config().get("from_address", "")

    provider_mark = f"""<tr><td style=\"padding:0 0 16px;color:#2b2038;font-size:14px;line-height:1.5\"><strong>Método de Acesso:</strong><br><span style=\"color:#5d4c70\">{escape(provider_label)}</span></td></tr>"""
    if user.auth_provider == "m365":
        provider_mark = f"""<tr><td style=\"padding:0 0 16px;color:#2b2038;font-size:14px;line-height:1.5\"><strong>Método de Acesso:</strong><br><table role=\"presentation\" cellpadding=\"0\" cellspacing=\"0\" border=\"0\" style=\"margin-top:7px\"><tr><td style=\"padding-right:9px\"><table role=\"presentation\" cellpadding=\"0\" cellspacing=\"0\" border=\"0\"><tr><td style=\"width:7px;height:7px;background-color:#f25022;font-size:0;line-height:0\">&nbsp;</td><td style=\"width:2px;font-size:0;line-height:0\">&nbsp;</td><td style=\"width:7px;height:7px;background-color:#7fba00;font-size:0;line-height:0\">&nbsp;</td></tr><tr><td style=\"height:2px;font-size:0;line-height:0\">&nbsp;</td><td style=\"font-size:0;line-height:0\">&nbsp;</td><td style=\"height:2px;font-size:0;line-height:0\">&nbsp;</td></tr><tr><td style=\"width:7px;height:7px;background-color:#00a4ef;font-size:0;line-height:0\">&nbsp;</td><td style=\"width:2px;font-size:0;line-height:0\">&nbsp;</td><td style=\"width:7px;height:7px;background-color:#ffb900;font-size:0;line-height:0\">&nbsp;</td></tr></table></td><td style=\"color:#2b2038;font-weight:bold;font-size:14px\">Microsoft 365</td></tr></table></td></tr>"""
    password_line = ""
    if temporary_password:
        password_line = f"<tr><td style=\"padding:0 0 16px;color:#2b2038;font-size:14px\"><strong>Senha temporária:</strong> <code style=\"color:#5d4c70\">{escape(temporary_password)}</code></td></tr>"
    html = f"""<!doctype html>
<html lang=\"pt-BR\" style=\"color-scheme:light only; supported-color-schemes:light\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\"><meta name=\"color-scheme\" content=\"light\"><meta name=\"supported-color-schemes\" content=\"light\"><title>Bem-vindo ao seu novo acesso</title></head>
<body style=\"margin:0;padding:0;background-color:#f4f1f7;color:#2b2038;font-family:Arial,Helvetica,sans-serif;line-height:1.55;color-scheme:light only\">
  <center role=\"article\" aria-roledescription=\"email\" lang=\"pt-BR\" style=\"width:100%;background-color:#f4f1f7\">
    <table role=\"presentation\" width=\"100%\" cellpadding=\"0\" cellspacing=\"0\" border=\"0\" bgcolor=\"#f4f1f7\" style=\"width:100%;background-color:#f4f1f7;border-collapse:collapse\"><tr><td align=\"center\" style=\"padding:24px 12px\">
      <!--[if mso]><table role=\"presentation\" width=\"600\" cellpadding=\"0\" cellspacing=\"0\" border=\"0\"><tr><td><![endif]-->
      <table role=\"presentation\" class=\"email-shell\" width=\"100%\" cellpadding=\"0\" cellspacing=\"0\" border=\"0\" style=\"width:100%;max-width:600px;border-collapse:separate;border-spacing:0\">
        <tr><td class=\"email-hero\" bgcolor=\"{secondary}\" style=\"padding:30px 32px;background-color:{secondary};color:#ffffff\"><table role=\"presentation\" width=\"100%\" cellpadding=\"0\" cellspacing=\"0\" border=\"0\"><tr><td style=\"color:#ffffff;font-size:13px;letter-spacing:2px;text-transform:uppercase\">{escape(suite)} · {escape(company)}</td></tr><tr><td style=\"padding-top:24px;color:#ffffff;font-size:29px;line-height:1.2;font-weight:700\">Bem-vindo a bordo</td></tr></table></td></tr>
        <tr><td class=\"email-card\" bgcolor=\"#ffffff\" style=\"padding:28px 32px 30px;background-color:#ffffff;border:1px solid #d9c8e8;color:#2b2038\"><table role=\"presentation\" width=\"100%\" cellpadding=\"0\" cellspacing=\"0\" border=\"0\"><tr><td style=\"padding:0 0 22px;color:#2b2038;font-size:15px;line-height:1.6\">Olá, <strong>{escape(name)}</strong>. Seu acesso ao portal foi preparado pela equipe da {escape(company)}.</td></tr><tr><td style=\"padding:0 0 10px;color:{secondary};font-size:12px;text-transform:uppercase;letter-spacing:1px;font-weight:700\">Dados de acesso</td></tr><tr><td style=\"padding:0 0 16px;color:#2b2038;font-size:14px\"><strong>Usuário:</strong> <span style=\"color:#5d4c70\">{escape(user.username or user.email)}</span></td></tr>{provider_mark}{password_line}<tr><td align=\"center\" style=\"padding:4px 0 24px\"><table role=\"presentation\" cellpadding=\"0\" cellspacing=\"0\" border=\"0\" align=\"center\"><tr><td align=\"center\" bgcolor=\"{secondary}\" style=\"border-radius:8px;background-color:{secondary}\"><a href=\"{escape(portal)}\" style=\"display:inline-block;padding:13px 25px;border:1px solid {secondary};border-radius:8px;color:#ffffff;text-decoration:none;font-size:15px;font-weight:700\">Abrir o Admin Center</a></td></tr></table></td></tr><tr><td style=\"padding:0;color:#5d4c70;font-size:13px;line-height:1.55\">Se precisar de ajuda, escreva para <a href=\"mailto:{escape(support_address)}\" style=\"color:{secondary};text-decoration:underline\">{escape(support_address)}</a>.</td></tr></table></td></tr>
        <tr><td align=\"center\" style=\"padding:16px 12px 0;color:#756681;font-size:12px\">{escape(company)} · {current_app.config.get('CURRENT_YEAR', '2026')}</td></tr>
      </table>
      <!--[if mso]></td></tr></table><![endif]-->
    </td></tr></table>
  </center>
</body></html>"""
    body = f"Olá, {name}. Seu acesso ao Admin Center da suíte {suite} foi criado. Usuário: {user.username or user.email}. Método: {provider_label}."
    if temporary_password:
        body += f" Senha temporária: {temporary_password}."
    body += f" Acesse: {portal}. Em caso de dúvida, contate {support_address}."
    send_notification([user.email], "Seu acesso ao Admin Center foi criado", body, html_body=html)


def send_test_email(recipient: str, smtp_config: dict | None = None) -> tuple[str, str]:
    company, primary, secondary = _branding()
    html = f"""<!doctype html><html lang=\"pt-BR\"><body style=\"margin:0;background:#08060c;color:#f7f3fb;font-family:Arial,sans-serif\"><div style=\"height:6px;background:linear-gradient(90deg,{primary},{secondary})\"></div><div style=\"max-width:620px;margin:32px auto;padding:32px;background:#120e18;border:1px solid #3a2949;border-radius:12px\"><div style=\"color:{secondary};font-size:13px;letter-spacing:2px;text-transform:uppercase\">{escape(company)}</div><h1 style=\"color:#fff\">E-mail de teste</h1><p>A configuração de envio de e-mail do Admin Center está respondendo corretamente.</p><p style=\"color:#bdb2c8\">Esta é uma mensagem de validação enviada pelo painel de configurações.</p></div></body></html>"""
    return send_notification([recipient], "Teste de e-mail — Admin Center", "A configuração de envio de e-mail está respondendo corretamente.", html_body=html, smtp_config=smtp_config)


def create_in_app_notifications(
    users: list[User], title: str, message: str, link: str = ""
) -> None:
    """Queue notifications in the panel transaction for the selected users."""
    seen: set[int] = set()
    for user in users:
        if not user.active or user.id in seen:
            continue
        seen.add(user.id)
        db.session.add(
            InAppNotification(
                user_id=user.id,
                title=title[:180],
                message=message[:2000],
                link=link[:512],
            )
        )
