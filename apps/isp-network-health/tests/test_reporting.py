from __future__ import annotations

import unittest
from datetime import datetime, timezone

from isp_health.reporting import build_health_pdf, build_report_model


def result(ip: str, blacklist: str, status: str = "not_listed") -> dict[str, object]:
    return {
        "target_kind": "ip",
        "target_value": ip,
        "blacklist": blacklist,
        "query_name": f"{ip}.{blacklist}",
        "status": status,
        "answers": ["127.0.0.2"] if status == "listed" else [],
        "duration_ms": 12,
    }


def scan(target: str = "203.0.113.0/30") -> dict[str, object]:
    return {
        "id": 12,
        "target": target,
        "target_kind": "cidr",
        "profile": "conservative",
        "status": "succeeded",
        "started_at": datetime(2026, 9, 16, 12, 0, tzinfo=timezone.utc),
        "finished_at": datetime(2026, 9, 16, 12, 0, 17, tzinfo=timezone.utc),
        "summary_json": {"risk_level": "Sem evidências relevantes"},
    }


class ReportingTests(unittest.TestCase):
    def test_report_has_one_row_per_ip_and_unique_blacklist_count(self) -> None:
        results = [
            result("203.0.113.1", "zen.spamhaus.org", "listed"),
            result("203.0.113.1", "bl.spamcop.net"),
            result("203.0.113.1", "b.barracudacentral.org"),
            result("203.0.113.2", "zen.spamhaus.org"),
            result("203.0.113.2", "bl.spamcop.net"),
            result("203.0.113.2", "b.barracudacentral.org"),
        ]

        model = build_report_model(scan(), results)

        self.assertEqual(model["stats"]["scanned_ips"], 2)
        self.assertEqual(model["stats"]["consulted_blacklists"], 3)
        self.assertEqual(model["stats"]["subnets_24"], 1)
        self.assertEqual(len(model["groups"]), 1)
        self.assertEqual(len(model["groups"][0]["rows"]), 2)
        self.assertEqual(model["groups"][0]["rows"][0]["detected_names"], ["zen.spamhaus.org"])

    def test_large_target_is_split_into_reference_subnets(self) -> None:
        model = build_report_model(
            scan("203.0.112.0/23"),
            [result("203.0.112.1", "zen.spamhaus.org"), result("203.0.113.1", "zen.spamhaus.org")],
        )

        self.assertEqual(model["stats"]["subnets_24"], 2)
        self.assertEqual([group["block"] for group in model["groups"]], ["203.0.112.0/24", "203.0.113.0/24"])

    def test_pdf_is_generated_internally(self) -> None:
        pdf = build_health_pdf(scan(), [result("203.0.113.1", "zen.spamhaus.org", "listed")])

        self.assertTrue(pdf.startswith(b"%PDF-"))
        self.assertGreater(len(pdf), 1000)

    def test_small_clean_target_stays_as_one_collapsed_block(self) -> None:
        model = build_report_model(
            scan(),
            [result("203.0.113.1", "zen.spamhaus.org"), result("203.0.113.2", "zen.spamhaus.org")],
        )

        self.assertEqual([group["block"] for group in model["groups"]], ["203.0.113.0/30"])
        self.assertFalse(model["groups"][0]["has_findings"])


if __name__ == "__main__":
    unittest.main()
