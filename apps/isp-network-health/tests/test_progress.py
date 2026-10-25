from __future__ import annotations

import os
import unittest
from unittest.mock import patch
from datetime import datetime, timedelta, timezone

os.environ.setdefault("APP_ENV", "development")

from isp_health.web import _scan_payload, app


class ScanProgressTests(unittest.TestCase):
    def test_recent_scans_internal_api_rejects_missing_or_invalid_token(self):
        with patch("isp_health.web._admin_scans_token", return_value="internal-test-token"):
            with app.test_client() as client:
                self.assertEqual(client.get("/internal/admin/recent-scans").status_code, 403)
                self.assertEqual(client.get("/internal/admin/recent-scans", headers={"X-ISP-Admin-Token": "invalid"}).status_code, 403)

    def test_recent_scans_internal_api_applies_subject_filter(self):
        with patch("isp_health.web._admin_scans_token", return_value="internal-test-token"), \
             patch("isp_health.web._ensure_schema"), \
             patch("isp_health.web.list_recent_scans", return_value=[]) as recent:
            with app.test_client() as client:
                response = client.get("/internal/admin/recent-scans?subject=42", headers={"X-ISP-Admin-Token": "internal-test-token"})
            self.assertEqual(response.status_code, 200)
            recent.assert_called_once_with(subject="42")

    def test_running_scan_exposes_percent_and_eta(self) -> None:
        scan = _scan_payload(
            {
                "id": 10,
                "status": "running",
                "total_checks": 100,
                "completed_checks": 25,
                "started_at": datetime.now(timezone.utc) - timedelta(seconds=100),
                "finished_at": None,
            }
        )

        self.assertEqual(scan["progress_percent"], 25)
        self.assertGreaterEqual(scan["eta_seconds"], 290)
        self.assertLessEqual(scan["eta_seconds"], 310)
        self.assertIn("Restante estimado", scan["eta_label"])

    def test_queued_scan_reports_that_it_is_waiting_for_worker(self) -> None:
        scan = _scan_payload(
            {
                "id": 11,
                "status": "queued",
                "total_checks": 0,
                "completed_checks": 0,
                "started_at": None,
                "finished_at": None,
            }
        )

        self.assertEqual(scan["progress_percent"], 0)
        self.assertIsNone(scan["eta_seconds"])
        self.assertEqual(scan["eta_label"], "Aguardando o worker")


if __name__ == "__main__":
    unittest.main()
