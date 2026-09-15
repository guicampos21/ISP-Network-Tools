from pathlib import Path

import pytest

from geofeed_admin import create_app
from geofeed_admin.models import Company, FeedEntry, NetworkBlock, User, db


@pytest.fixture()
def app(tmp_path: Path):
    database = tmp_path / "test.sqlite3"
    app = create_app(
        {
            "TESTING": True,
            "APP_ENV": "development",
            "DEV_AUTH": True,
            "SECRET_KEY": "test-secret-not-for-production",
            "SQLALCHEMY_DATABASE_URI": f"sqlite:///{database}",
            "DATABASE_PATH": str(database),
            "PUBLIC_ROOT": str(tmp_path / "publish"),
            "BACKUP_ROOT": str(tmp_path / "backups"),
            "BRANDING_ROOT": str(tmp_path / "branding"),
            "AVATAR_ROOT": str(tmp_path / "avatars"),
            "PUBLIC_BASE_URL": "https://geofeed.example.test",
            "ADMIN_BASE_URL": "https://admin-center.example.test",
            "TRUSTED_HOSTS": ["localhost", "admin-center.example.test"],
            "SESSION_COOKIE_SECURE": False,
            "WTF_CSRF_ENABLED": False,
            "RATELIMIT_ENABLED": False,
            "ENTRA_CLIENT_SECRET": "never-render-this-secret",
            "ENTRA_CLIENT_ID": "",
            "ENTRA_TENANT_ID": "",
        }
    )
    with app.app_context():
        db.create_all()
        admin = User(email="admin@example.test", display_name="Admin", role="admin", active=True)
        editor = User(email="editor@example.test", display_name="Editor", role="editor", active=True)
        viewer = User(email="viewer@example.test", display_name="Viewer", role="viewer", active=True)
        db.session.add_all([admin, editor, viewer])
        company = Company(name="Example ISP", default_asn=265264, active=True)
        db.session.add(company)
        db.session.flush()
        block = NetworkBlock(
            cidr="168.90.48.0/22",
            ip_version=4,
            company_id=company.id,
            asn=265264,
            filename="geofeed168.csv",
            active=True,
        )
        db.session.add(block)
        db.session.flush()
        db.session.add(
            FeedEntry(
                block_id=block.id,
                prefix="168.90.48.0/24",
                alpha2code="BR",
                region="BR-PR",
                city="Curitiba",
                postal_code="",
                sort_order=0,
            )
        )
        db.session.commit()
    yield app


@pytest.fixture()
def client(app):
    return app.test_client()


def login_as(client, app, email: str):
    with app.app_context():
        user = User.query.filter_by(email=email).one()
        user_id = user.id
    with client.session_transaction() as session:
        session["user_id"] = user_id
    return user_id
