from __future__ import annotations

import unittest
import hashlib
import hmac
from datetime import datetime, timedelta, timezone
from unittest.mock import patch

from isp_health.web import app, limiter


class ScanManagementTests(unittest.TestCase):
    def setUp(self) -> None:
        self.client = app.test_client()
        limiter.enabled = False
        self.presence = patch("isp_health.web._touch_presence", return_value=True)
        self.schema = patch("isp_health.web._ensure_schema")
        self.presence.start()
        self.schema.start()

    def tearDown(self) -> None:
        self.schema.stop()
        self.presence.stop()
        limiter.enabled = True

    def login(self, subject: str, profile: str) -> str:
        with self.client.session_transaction() as session:
            session["health_user"] = {"sub": subject, "email": f"{subject}@example.com", "name": subject,
                                      "profile": profile, "apps": ["isp_network_health"]}
            session["csrf_token"] = "test-csrf"
        return "test-csrf"

    def test_admin_live_scans_only_load_bounded_recent_results(self) -> None:
        scan = {"id": 15, "status": "running", "target": "186.198.128.0/17",
                "target_kind": "cidr", "profile": "aggressive", "total_checks": 5111808,
                "completed_checks": 512250, "requester_email": "user@example.com"}
        secret = "test-admin-scans-secret"
        token = hmac.new(secret.encode(), b"isp-network-tools:admin-scans:v1", hashlib.sha256).hexdigest()
        with patch.dict(app.config, {"SSO_SIGNING_SECRET": secret}), \
             patch("isp_health.web.list_active_scans_for_admin", return_value=[scan]), \
             patch("isp_health.web.list_recent_results", return_value=[{"target_value": "127.0.0.2", "blacklist": "example.org", "status": "listed", "answers": []}]) as recent, \
             patch("isp_health.web.list_results") as all_results:
            response = self.client.get("/internal/admin/scans?details=1", headers={"X-ISP-Admin-Token": token})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(len(response.json["scans"][0]["results"]), 1)
        recent.assert_called_once_with(15)
        all_results.assert_not_called()

    def test_regular_user_cannot_view_user_scans_or_resume_another_scan(self) -> None:
        token = self.login("7", "health_operator")
        scan = {"id": 42, "requester_subject": "8", "requester_email": "8@example.com", "status": "failed"}
        with patch("isp_health.web.get_scan", return_value=scan), patch("isp_health.web.requeue_scan") as requeue:
            self.assertEqual(self.client.get("/users/scans").status_code, 403)
            self.assertEqual(self.client.post("/scans/42/resume", data={"csrf_token": token}).status_code, 403)
        requeue.assert_not_called()

    def test_superadmin_directory_role_is_verified_before_listing(self) -> None:
        self.login("1", "super_admin")
        with patch("isp_health.web._health_directory", return_value=[{"subject": "1", "role": "admin"}]), \
             patch("isp_health.web.list_all_scans") as listing:
            self.assertEqual(self.client.get("/users/scans").status_code, 403)
        listing.assert_not_called()

    def test_superadmin_can_view_paginated_history(self) -> None:
        self.login("1", "super_admin")
        directory = [{"subject": "1", "email": "1@example.com", "name": "Admin", "role": "super_admin"},
                     {"subject": "8", "email": "8@example.com", "name": "Operador", "role": "health_operator"}]
        with patch("isp_health.web._health_directory", return_value=directory), \
             patch("isp_health.web.list_all_scans", return_value=([], 0)) as listing:
            response = self.client.get("/users/scans?subject=8")
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Scan dos usu", response.data)
        listing.assert_called_once_with(subject="8", limit=50, offset=0)

    def test_superadmin_starts_scan_for_selected_user(self) -> None:
        token = self.login("1", "super_admin")
        directory = [{"subject": "1", "email": "1@example.com", "role": "super_admin"},
                     {"subject": "8", "email": "8@example.com", "role": "health_operator"}]
        with patch("isp_health.web._health_directory", return_value=directory), \
             patch("isp_health.web._queue_scan", return_value=42) as queue:
            response = self.client.post("/users/scans", data={"csrf_token": token, "subject": "8",
                                                              "target": "127.0.0.2", "profile": "conservative"})
        self.assertEqual(response.status_code, 302)
        queue.assert_called_once_with(directory[1], "127.0.0.2", "ip", "conservative")

    def test_superadmin_resumes_failed_user_scan_with_same_id(self) -> None:
        token = self.login("1", "super_admin")
        scan = {"id": 42, "requester_subject": "8", "requester_email": "8@example.com", "status": "failed"}
        directory = [{"subject": "1", "email": "1@example.com", "role": "super_admin"}]
        with patch("isp_health.web._health_directory", return_value=directory), \
             patch("isp_health.web.get_scan", return_value=scan), \
             patch("isp_health.web._redis") as redis, \
             patch("isp_health.web.requeue_scan", return_value=scan) as requeue:
            redis.return_value.set.return_value = True
            response = self.client.post("/scans/42/resume", data={"csrf_token": token})
        self.assertEqual(response.status_code, 302)
        self.assertIn("/users/scans?subject=8", response.location)
        self.assertIsNone(requeue.call_args.args[1])
        redis.return_value.lpush.assert_called_once()

    def test_history_row_shows_scan_context_and_expansion_keeps_error(self) -> None:
        self.login("1", "super_admin")
        started = datetime(2026, 9, 22, 3, 7, tzinfo=timezone.utc)
        scan = {
            "id": 42, "requester_subject": "8", "requester_email": "8@example.com",
            "target": "186.198.128.0/17", "target_kind": "cidr", "profile": "aggressive",
            "status": "failed", "total_checks": 5111808, "completed_checks": 469250,
            "created_at": started, "started_at": started,
            "finished_at": started + timedelta(hours=2, minutes=3),
            "error_message": "Falha de comunicação com o banco de dados.",
        }
        directory = [{"subject": "1", "email": "1@example.com", "name": "Admin", "role": "super_admin"},
                     {"subject": "8", "email": "8@example.com", "name": "Operador", "role": "health_operator"}]
        with patch("isp_health.web._health_directory", return_value=directory), \
             patch("isp_health.web.list_all_scans", return_value=([scan], 1)), \
             patch("isp_health.web.list_scans", return_value=[scan]), \
             patch("isp_health.web.get_scan", return_value=scan), \
             patch("isp_health.web.list_scan_events", return_value=[]):
            history = self.client.get("/users/scans?subject=8")
            detail = self.client.get("/scans/42")
            report_only = self.client.get("/scans/42/report")
        self.assertEqual(history.status_code, 200)
        self.assertEqual(detail.status_code, 200)
        self.assertIn(b'class="scan-row-meta"', history.data)
        self.assertIn("2h 03min".encode(), history.data)
        self.assertIn("Agressivo".encode(), history.data)
        self.assertNotIn("Falha de comunicação".encode(), history.data)
        self.assertIn("Falha de comunicação".encode(), detail.data)
        self.assertNotIn(b'class="report-meta"', detail.data)
        self.assertEqual(report_only.status_code, 200)
        self.assertIn(b'class="report-meta"', report_only.data)
        self.assertIn(b"2h 03min", report_only.data)

    def test_large_completed_scan_pdf_uses_persisted_summary_without_loading_all_checks(self) -> None:
        self.login("7", "health_operator")
        started = datetime(2026, 9, 30, 13, 57, 44, tzinfo=timezone.utc)
        scan = {
            "id": 16,
            "requester_subject": "7",
            "requester_email": "7@example.com",
            "target": "186.198.128.0/17",
            "target_kind": "cidr",
            "profile": "conservative",
            "status": "succeeded",
            "total_checks": 5_111_808,
            "completed_checks": 5_111_808,
            "created_at": started,
            "started_at": started,
            "finished_at": started + timedelta(days=1, hours=20, minutes=52),
            "summary_json": {
                "risk_level": "Alto",
                "unique_ips_scanned": 32_768,
                "unique_ips_listed": 24,
                "unique_ips_clean": 32_744,
                "listed_results": 31,
                "timeout_results": 18,
                "error_results": 2,
                "top_blacklists": [{"name": "zen.spamhaus.org", "count": 12}],
                "listed_ips": [["186.198.128.1", ["zen.spamhaus.org"]]],
            },
        }
        with patch("isp_health.web.get_scan", return_value=scan), \
             patch("isp_health.web.list_scan_events", return_value=[]), \
             patch("isp_health.web.list_scans", return_value=[scan]), \
             patch("isp_health.web.list_results", side_effect=AssertionError("large result set must not be materialized")) as results:
            page = self.client.get("/scans/16/report")
            block = self.client.get("/api/scans/16/report-block?block=186.198.128.0/24")
            response = self.client.get("/scans/16/report.pdf")

        self.assertEqual(page.status_code, 200)
        self.assertIn(b"32768", page.data)
        self.assertIn(b"156", page.data)
        self.assertIn(b"186.198.128.0/24", page.data)
        self.assertIn(b"0.39%", page.data)
        self.assertIn("volume elevado de consultas".encode(), page.data)
        self.assertEqual(block.status_code, 200)
        self.assertIn(b"186.198.128.1", block.data)
        self.assertIn(b"Listado (1)", block.data)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.mimetype, "application/pdf")
        self.assertTrue(response.data.startswith(b"%PDF-"))
        results.assert_not_called()


if __name__ == "__main__":
    unittest.main()
