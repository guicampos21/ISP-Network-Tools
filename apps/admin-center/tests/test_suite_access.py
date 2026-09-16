from geofeed_admin.models import (
    Application,
    Group,
    GroupApplicationGrant,
    User,
    UserApplicationGrant,
    db,
)

def login_as(client, app, email):
    with app.app_context():
        user_id = User.query.filter_by(email=email).one().id
    with client.session_transaction() as session:
        session["user_id"] = user_id


def test_development_cookies_are_compatible_with_local_http(app):
    assert app.config["SESSION_COOKIE_NAME"] == "isp_network_tools"
    assert app.config["REMEMBER_COOKIE_NAME"] == "geofeed_remember"


def test_application_access_is_deny_by_default_and_honors_group_and_direct_grants(app):
    with app.app_context():
        user = User.query.filter_by(email="viewer@example.test").one()
        health = Application.query.filter_by(code="isp_network_health").one()
        group = Group(name="NOC", description="Operações")
        group.users.append(user)
        group.application_grants.append(
            GroupApplicationGrant(application=health, allowed=True)
        )
        db.session.add(group)
        db.session.commit()
        assert user.has_application_access("isp_network_health")

        user.application_grants.append(
            UserApplicationGrant(application=health, allowed=False)
        )
        db.session.commit()
        assert not user.has_application_access("isp_network_health")
        assert user.has_application_access("geofeed_public")


def test_only_superadmin_can_manage_application_access(client, app):
    assert client.get("/access/applications").status_code == 302
    login_as(client, app, "admin@example.test")
    assert client.get("/access/applications").status_code == 403

    with app.app_context():
        User.query.filter_by(email="admin@example.test").one().role = "super_admin"
        db.session.commit()
    response = client.get("/access/applications")
    assert response.status_code == 200
    assert b"ISP Network Health" in response.data


def test_superadmin_login_opens_operational_overview(client, app):
    with app.app_context():
        User.query.filter_by(email="admin@example.test").one().role = "super_admin"
        db.session.commit()

    response = client.post("/dev-login")

    assert response.status_code == 302
    assert response.headers["Location"].endswith("/")


def test_application_launcher_has_search_and_semantic_icons(client, app):
    with app.app_context():
        User.query.filter_by(email="admin@example.test").one().role = "super_admin"
        db.session.commit()
    login_as(client, app, "admin@example.test")
    html = client.get("/access/applications").get_data(as_text=True)

    assert 'data-app-launcher' in html
    assert 'data-launcher-search' in html
    assert 'class="launcher-grid-icon"' in html
    assert 'app-icon-geofeed' in html
    assert 'app-icon-admin' in html
    assert 'app-icon-health' in html
    assert 'href="/"' in html


def test_operational_dashboard_has_the_new_layout(client, app):
    login_as(client, app, "admin@example.test")

    html = client.get("/").get_data(as_text=True)

    assert "Visão geral" in html
    assert "Usuários Online" in html
    assert "Scans Rodando" in html
    assert "Últimos blocos escaneados" in html
    assert "Saúde dos arquivos públicos" not in html
    assert "Ranking de atualizações" not in html
    assert "data-rfc-toggle" in html


def test_operational_activity_routes_follow_role_boundaries(client, app, monkeypatch):
    login_as(client, app, "admin@example.test")
    assert client.get("/users/online").status_code == 200
    assert client.get("/scans/running").status_code == 403

    with app.app_context():
        User.query.filter_by(email="admin@example.test").one().role = "super_admin"
        db.session.commit()
    monkeypatch.setattr(
        "geofeed_admin.routes._fetch_running_scans",
        lambda: {"available": True, "scans": []},
    )
    assert client.get("/scans/running").status_code == 200

    login_as(client, app, "editor@example.test")
    assert client.get("/users/online").status_code == 403
