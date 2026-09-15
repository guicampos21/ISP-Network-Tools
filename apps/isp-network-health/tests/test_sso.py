import os
import unittest
from unittest.mock import patch

from isp_health.config import app_config
from isp_shared.sso import HandoffError, issue_handoff, verify_handoff


class SsoHandoffTests(unittest.TestCase):
    def test_cookie_name_matches_transport_security(self):
        with patch.dict(os.environ, {"APP_ENV": "development"}):
            self.assertEqual(app_config()["SESSION_COOKIE_NAME"], "isp_network_health")
        with patch.dict(os.environ, {"APP_ENV": "production"}):
            self.assertEqual(app_config()["SESSION_COOKIE_NAME"], "__Host-isp_network_health")

    def test_signed_handoff_round_trips(self):
        token = issue_handoff(
            "test-signing-secret",
            subject="42",
            email="operator@example.test",
            display_name="Operator",
            role="admin",
            applications=["isp_network_health"],
            audience="isp_network_health",
        )
        payload = verify_handoff(
            token,
            "test-signing-secret",
            audience="isp_network_health",
        )
        self.assertEqual(payload["sub"], "42")
        self.assertEqual(payload["email"], "operator@example.test")

    def test_tampered_or_wrong_audience_handoff_is_rejected(self):
        token = issue_handoff(
            "test-signing-secret",
            subject="42",
            email="operator@example.test",
            display_name="Operator",
            role="admin",
            applications=["isp_network_health"],
            audience="isp_network_health",
        )
        encoded, signature = token.split(".")
        with self.assertRaises(HandoffError):
            verify_handoff(
                f"{encoded[:-1]}{('A' if encoded[-1] != 'A' else 'B')}.{signature}",
                "test-signing-secret",
                audience="isp_network_health",
            )
        with self.assertRaises(HandoffError):
            verify_handoff(token, "test-signing-secret", audience="other-app")
