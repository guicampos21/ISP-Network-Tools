import json
from pathlib import Path

from geofeed_admin.geofeed import (
    build_snapshot,
    generate_csv,
    generate_company_csv,
    parse_csv,
    publish_snapshot,
    validate_geofeed_content,
    validate_snapshot,
)


def test_snapshot_is_valid(app):
    with app.app_context():
        result = validate_snapshot(build_snapshot())
    assert result.valid
    assert result.errors == []


def test_rejects_prefix_outside_parent(app):
    with app.app_context():
        snapshot = build_snapshot()
    snapshot["blocks"][0]["entries"][0]["prefix"] = "203.0.113.0/24"
    result = validate_snapshot(snapshot)
    assert not result.valid
    assert any("não pertence" in item for item in result.errors)


def test_rejects_path_traversal_filename(app):
    with app.app_context():
        snapshot = build_snapshot()
    snapshot["blocks"][0]["filename"] = "../../segredo.csv"
    result = validate_snapshot(snapshot)
    assert not result.valid
    assert any("nome de arquivo inválido" in item for item in result.errors)


def test_rejects_spreadsheet_formula(app):
    with app.app_context():
        snapshot = build_snapshot()
    snapshot["blocks"][0]["entries"][0]["city"] = "=HYPERLINK(exemplo)"
    result = validate_snapshot(snapshot)
    assert not result.valid
    assert any("operador de planilha" in item for item in result.errors)


def test_csv_is_utf8_crlf_and_roundtrips(app):
    with app.app_context():
        block = build_snapshot()["blocks"][0]
    content = generate_csv(block)
    assert b"\r\n" in content
    assert b"\n" not in content.replace(b"\r\n", b"")
    entries = parse_csv(content)
    assert entries[0]["prefix"] == "168.90.48.0/24"
    assert entries[0]["city"] == "Curitiba"


def test_publish_is_atomic_and_creates_backup(app, tmp_path: Path):
    with app.app_context():
        snapshot = build_snapshot()
    public = tmp_path / "public"
    backups = tmp_path / "backups"
    archive = publish_snapshot(
        snapshot, str(public), str(backups), "https://geofeed.example.test"
    )
    assert (public / "geofeed168.csv").is_file()
    manifest = json.loads((public / "geofeed-manifest.json").read_text())
    assert manifest["feeds"][0]["csv_url"].startswith("https://geofeed.example.test/")
    assert Path(archive).is_file()
    assert not list(public.glob(".geofeed-stage-*"))
    assert (public / "geofeed-example-isp.csv").is_file()
    assert manifest["companies"][0]["csv_url"] == "https://geofeed.example.test/geofeed-example-isp.csv"
    assert b"168.90.48.0/24" in (public / "geofeed-example-isp.csv").read_bytes()


def test_published_geofeed_content_is_rfc_compliant(app):
    with app.app_context():
        block = build_snapshot()["blocks"][0]
    result = validate_geofeed_content(generate_csv(block), expected_block=block)
    assert result.valid
    assert result.entry_count == 1


def test_geofeed_content_reports_format_and_semantic_failures(app):
    with app.app_context():
        block = build_snapshot()["blocks"][0]
    content = (
        b"168.90.48.0/24,XX,XX-NOTREAL,Curitiba,\r\n"
        b"168.90.48.0/24,BR,BR-PR,Curitiba,\r\n"
        b"# comentario com terminador incorreto\n"
    )
    result = validate_geofeed_content(content, expected_block=block)
    assert not result.valid
    assert any("CRLF" in error for error in result.errors)
    assert any("país" in error for error in result.errors)
    assert any("duplicado" in error for error in result.errors)
