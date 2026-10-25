from pathlib import Path

from geofeed_admin.geofeed import build_snapshot
from geofeed_admin.models import ChangeRequest, HealthCheck, InAppNotification, NetworkBlock, Publication, User, db
from geofeed_admin.operations import publish, run_healthchecks
from geofeed_admin.settings import set_setting

from .conftest import login_as


def test_admin_pages_render_without_internal_errors(client, app):
    with app.app_context():
        User.query.filter_by(email="admin@example.test").one().role = "super_admin"
        db.session.commit()
    login_as(client, app, "admin@example.test")
    paths = [
        "/",
        "/companies",
        "/blocks",
        "/blocks/1",
        "/users",
        "/changes",
        "/changes/submit",
        "/history",
        "/audit",
        "/monitoring",
        "/working/geofeeds.zip",
        "/blocks/1/preview.csv",
    ]
    for path in paths:
        response = client.get(path)
        assert response.status_code == 200, path
        assert b"never-render-this-secret" not in response.data


def test_dashboard_has_no_manual_publish_or_zip_actions(client, app):
    login_as(client, app, "admin@example.test")
    dashboard = client.get("/").get_data(as_text=True)
    blocks = client.get("/blocks").get_data(as_text=True)
    assert "Publicar agora" not in dashboard
    assert "Baixar prévia ZIP" not in dashboard
    assert "Baixar prévia ZIP" in blocks
    assert client.get("/publish-direct").status_code == 404


def test_editor_submission_and_independent_admin_approval(client, app):
    login_as(client, app, "editor@example.test")
    response = client.post(
        "/changes/submit",
        data={"title": "Publicação inicial", "notes": "Revisão da engenharia"},
    )
    assert response.status_code == 302
    with app.app_context():
        change = ChangeRequest.query.one()
        assert change.status == "pending"
        change_id = change.id

    login_as(client, app, "admin@example.test")
    response = client.post(
        f"/changes/{change_id}/approve",
        data={"review_notes": "Conferido"},
        follow_redirects=True,
    )
    assert response.status_code == 200
    assert "Publicação v1 concluída" in response.get_data(as_text=True)
    with app.app_context():
        assert ChangeRequest.query.one().status == "approved"
        assert Publication.query.one().version == 1


def test_admin_cannot_approve_own_request(client, app):
    admin_id = login_as(client, app, "admin@example.test")
    client.post("/changes/submit", data={"title": "Alteração do administrador"})
    with app.app_context():
        change = ChangeRequest.query.one()
        assert change.requested_by_id == admin_id
        change_id = change.id
    response = client.post(f"/changes/{change_id}/approve", follow_redirects=True)
    assert "não pode aprovar a própria" in response.get_data(as_text=True)
    with app.app_context():
        assert ChangeRequest.query.one().status == "pending"
        assert Publication.query.count() == 0


def test_editor_block_edit_creates_approval_without_mutating_working_data(client, app):
    login_as(client, app, "editor@example.test")
    response = client.post(
        "/blocks/1/edit",
        data={
            "cidr": "168.90.48.0/22",
            "company_id": "1",
            "asn": "265264",
            "filename": "geofeed168.csv",
            "description": "Atualizado pela engenharia",
            "active": "on",
            "notes": "Atualização solicitada pela engenharia.",
            "confirm_changes": "yes",
        },
    )
    assert response.status_code == 302
    with app.app_context():
        change = ChangeRequest.query.one()
        assert change.status == "pending"
        assert InAppNotification.query.filter_by(user_id=1).count() == 1
        assert NetworkBlock.query.one().description == ""


def test_admin_block_edit_requires_review_confirmation(client, app):
    login_as(client, app, "admin@example.test")
    response = client.post(
        "/blocks/1/edit",
        data={
            "cidr": "168.90.48.0/22",
            "company_id": "1",
            "asn": "265264",
            "filename": "geofeed168.csv",
            "description": "Tentativa sem revisão",
            "active": "on",
        },
        follow_redirects=True,
    )
    assert "Revise o resumo das alterações" in response.get_data(as_text=True)
    with app.app_context():
        assert NetworkBlock.query.one().description == ""
        assert Publication.query.count() == 0


def test_admin_block_edit_publishes_after_confirmation(client, app):
    login_as(client, app, "admin@example.test")
    response = client.post(
        "/blocks/1/edit",
        data={
            "cidr": "168.90.48.0/22",
            "company_id": "1",
            "asn": "265264",
            "filename": "geofeed168.csv",
            "description": "Publicado após revisão",
            "active": "on",
            "confirm_changes": "yes",
        },
        follow_redirects=True,
    )
    assert response.status_code == 200
    assert "Publicação v1 concluída" in response.get_data(as_text=True)
    with app.app_context():
        assert NetworkBlock.query.one().description == "Publicado após revisão"
        assert Publication.query.one().version == 1


def test_blocks_bulk_controls_use_direct_values_without_field_checkboxes(client, app):
    login_as(client, app, "admin@example.test")
    response = client.get("/blocks")
    html = response.get_data(as_text=True)
    assert response.status_code == 200
    assert 'name="fields"' not in html
    assert 'name="active"' in html
    assert 'name="company_id"' in html
    assert 'name="asn"' in html
    assert 'name="description"' in html
    assert "data-change-review" in html
    assert 'name="confirm_changes"' in html


def test_settings_contains_access_tabs_and_graphical_avatar_options(client, app):
    with app.app_context():
        from geofeed_admin.models import User
        User.query.filter_by(email="admin@example.test").one().role = "super_admin"
        db.session.commit()
    login_as(client, app, "admin@example.test")
    response = client.get("/settings?section=access")
    html = response.get_data(as_text=True)
    assert response.status_code == 200
    assert 'data-settings-panel="access"' in html
    for tab in ("users", "roles", "sectors", "functions"):
        assert f'data-access-tab="{tab}"' in html
    assert 'data-theme-preset=' in html
    avatar_response = client.get("/users/new")
    avatar_html = avatar_response.get_data(as_text=True)
    assert 'data-dicebear-catalog=' in avatar_html
    assert 'data-dicebear-controls' in avatar_html
    assert 'data-avatar-cancel' in avatar_html
    assert 'data-dicebear-random' in avatar_html
    assert 'data-photo-preview' in avatar_html


def test_login_uses_one_shared_remember_choice_below_local_form(client):
    html = client.get("/login").get_data(as_text=True)
    assert "Entre com sua conta" in html
    assert html.count("Manter conectado neste dispositivo") == 1
    assert "Nenhuma senha Microsoft" not in html
    if "Ou entre com:" in html:
        assert html.index("Entrar com conta local") < html.index("Ou entre com:")


def test_super_admin_soft_deletes_user_but_not_self(client, app):
    with app.app_context():
        admin = User.query.filter_by(email="admin@example.test").one()
        admin.role = "super_admin"
        target = User.query.filter_by(email="editor@example.test").one()
        target_id = target.id
        db.session.commit()
    login_as(client, app, "admin@example.test")
    response = client.post(f"/users/{target_id}/delete")
    assert response.status_code == 302
    with app.app_context():
        target = db.session.get(User, target_id)
        assert target.deleted_at is not None
        assert target.active is False
    self_response = client.post("/users/1/delete", follow_redirects=True)
    assert "não pode excluir o usuário conectado" in self_response.get_data(as_text=True)


def test_sector_in_use_cannot_be_deleted(client, app):
    with app.app_context():
        from geofeed_admin.models import Sector
        admin = User.query.filter_by(email="admin@example.test").one()
        admin.role = "super_admin"
        admin.department = "Infraestrutura"
        sector = Sector.query.filter_by(name="Infraestrutura").one()
        db.session.commit()
        sector_id = sector.id
    login_as(client, app, "admin@example.test")
    response = client.post(f"/access/sectors/{sector_id}/delete", follow_redirects=True)
    assert "setor usado por" in response.get_data(as_text=True)


def test_monitoring_opens_and_recovers_incident_with_rfc_validation(app, monkeypatch):
    with app.app_context():
        admin = User.query.filter_by(email="admin@example.test").one()
        publish(build_snapshot(), admin, "Teste de monitoramento")
        set_setting("monitoring.failure_threshold", "1", user=admin)
        set_setting("monitoring.retries", "0", user=admin)
        set_setting("monitoring.recipients", "noc@example.test", user=admin)
        db.session.commit()
        expected = Path(app.config["PUBLIC_ROOT"]) / "geofeed168.csv"
        content = expected.read_bytes()

        class FakeResponse:
            def __init__(self, status_code, body):
                self.status_code = status_code
                self.content = body
                self.headers = {"Content-Type": "application/geofeed+csv"}

        responses = [FakeResponse(503, b""), FakeResponse(200, content)]
        notices = []
        monkeypatch.setattr("geofeed_admin.operations.requests.get", lambda *args, **kwargs: responses.pop(0))
        monkeypatch.setattr("geofeed_admin.operations.send_notification", lambda recipients, subject, body: notices.append((recipients, subject, body)))
        assert run_healthchecks(trigger="manual") == (0, 1)
        assert HealthCheck.query.order_by(HealthCheck.id.desc()).first().incident_open is True
        assert run_healthchecks(trigger="manual") == (1, 1)
        latest = HealthCheck.query.order_by(HealthCheck.id.desc()).first()
        assert latest.incident_open is False
        assert any("Falha" in subject for _, subject, _ in notices)
        assert any("recuperado" in subject for _, subject, _ in notices)


def test_monitoring_settings_are_saved_and_return_to_same_tab(client, app):
    with app.app_context():
        admin = User.query.filter_by(email="admin@example.test").one()
        admin.role = "super_admin"
        db.session.commit()
    login_as(client, app, "admin@example.test")
    response = client.post(
        "/settings",
        data={
            "settings_section": "general",
            "settings_tab": "monitoring",
            "local_enabled": "on",
            "email_mode": "smtp",
            "smtp_provider": "other",
            "smtp_port": "587",
            "smtp_security": "starttls",
            "smtp_auth_method": "password",
            "smtp_from_name": "Geofeed",
            "smtp_from_address": "geofeed@example.com",
            "smtp_timeout": "15",
            "company_name": "Example ISP",
            "primary_color": "#5619a3",
            "secondary_color": "#7c32c7",
            "accent_color": "#b786f4",
            "background_start": "#09070d",
            "background_end": "#180d2c",
            "background_gradient": "on",
            "timezone": "America/Sao_Paulo",
            "password_min_length": "12",
            "password_require_upper": "on",
            "password_require_lower": "on",
            "password_require_number": "on",
            "password_require_symbol": "on",
            "monitoring_after_publish_enabled": "on",
            "monitoring_periodic_enabled": "on",
            "monitoring_periodic_interval_minutes": "90",
            "monitoring_timeout_seconds": "10",
            "monitoring_retries": "2",
            "monitoring_failure_threshold": "2",
            "monitoring_repeat_alert_minutes": "120",
            "monitoring_notify_recovery": "on",
            "monitoring_validate_content": "on",
            "monitoring_recipients": "noc@example.com; redes@example.com",
        },
    )
    assert response.status_code == 302
    assert response.headers["Location"].endswith("/settings?section=general&tab=monitoring")
    with app.app_context():
        from geofeed_admin.settings import get_setting
        assert get_setting("monitoring.periodic_interval_minutes") == "90"
        assert get_setting("monitoring.recipients") == "noc@example.com,redes@example.com"
