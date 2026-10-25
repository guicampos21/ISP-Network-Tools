from pathlib import Path

from flask import send_from_directory


def register_suite_assets(app):
    directory = Path(__file__).parent / "static"

    @app.get("/suite-assets/header.css", endpoint="suite_header_css")
    def suite_header_css():
        return send_from_directory(directory, "suite-header.css", mimetype="text/css")
