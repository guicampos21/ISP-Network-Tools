from __future__ import annotations

import unittest
from datetime import datetime, timezone

from isp_health.reporting import (
    build_health_pdf, build_report_model, build_summary_block_rows, build_summary_report_model,
    compact_listed_ip_results, scan_reference,
)


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
    def test_individual_ip_preserves_32_scope_without_inventing_24_subnets(self):
        individual = {**scan("127.0.0.2"), "target_kind": "ip"}
        model = build_report_model(individual, [result("127.0.0.2", "bl.spamcop.net", "timeout")])
        self.assertEqual(model["groups"][0]["block"], "127.0.0.2/32")
        self.assertEqual(model["groups"][0]["display_block"], "127.0.0.2")
        self.assertEqual(model["stats"]["subnets_24"], 0)
        self.assertEqual(model["stats"]["scope_value"], "127.0.0.2/32")
        self.assertNotIn("/24", model["stats"]["coverage_description"])

    def test_cidr_scope_counts_only_actual_24_subnets(self):
        for target, expected in [("203.0.113.2/32", 0), ("203.0.113.0/30", 0), ("203.0.113.0/25", 0), ("203.0.113.0/24", 1), ("203.0.112.0/23", 2)]:
            with self.subTest(target=target):
                model = build_report_model(scan(target), [result("203.0.113.2", "bl.spamcop.net")])
                self.assertEqual(model["stats"]["subnets_24"], expected)
                if expected == 0:
                    self.assertEqual(model["groups"][0]["block"], target)
    def test_scan_reference_is_stable_and_distinct_for_simultaneous_scans(self) -> None:
        first = {"id": 1, "created_at": datetime(2026, 9, 18, 16, 0, tzinfo=timezone.utc)}
        second = {**first, "id": 2}
        self.assertIn("20260918-160000", scan_reference(first))
        self.assertEqual(scan_reference(first), scan_reference(dict(first)))
        self.assertNotEqual(scan_reference(first), scan_reference(second))

    def test_all_timeouts_are_inconclusive_instead_of_clean(self) -> None:
        model = build_report_model(scan(), [result("203.0.113.1", "zen.spamhaus.org", "timeout")])
        self.assertEqual(model["stats"]["risk_level"], "Inconclusivo")
        self.assertEqual(model["stats"]["clean_ips"], 0)
        self.assertEqual(model["groups"][0]["tone"], "warning")

    def test_domain_detections_are_visible_without_resolved_ips(self) -> None:
        domain_scan = scan("dbltest.com")
        domain_scan["target_kind"] = "domain"
        check = result("dbltest.com", "dbl.spamhaus.org", "listed")
        check["target_kind"] = "domain"
        model = build_report_model(domain_scan, [check])
        self.assertEqual(model["stats"]["listed_domains"], 1)
        self.assertTrue(model["groups"][0]["has_findings"])

    def test_chart_categories_do_not_count_an_ip_twice(self) -> None:
        model = build_report_model(scan(), [
            result("203.0.113.1", "zen.spamhaus.org", "listed"),
            result("203.0.113.1", "bl.spamcop.net", "timeout"),
            result("203.0.113.2", "bl.spamcop.net"),
            result("203.0.113.3", "bl.spamcop.net", "timeout"),
        ])
        self.assertEqual([item["count"] for item in model["charts"]["distribution"]], [1, 1, 1])

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
        self.assertEqual(model["stats"]["subnets_24"], 0)
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

    def test_large_scan_summary_model_uses_persisted_aggregates(self) -> None:
        large_scan = {
            **scan("186.198.128.0/17"),
            "total_checks": 5_111_808,
            "summary_json": {
                "risk_level": "Alto",
                "total_checks": 5_111_808,
                "unique_ips_scanned": 32_768,
                "unique_ips_listed": 24,
                "unique_ips_clean": 32_744,
                "timeout_results": 18,
                "error_results": 2,
                "top_blacklists": [["zen.spamhaus.org", 12]],
                "listed_ips": [
                    [f"186.198.128.{host}", ["zen.spamhaus.org"]]
                    for host in range(24)
                ],
            },
        }

        model = build_summary_report_model(large_scan)

        self.assertTrue(model["stats"]["summary_only"])
        self.assertEqual(model["stats"]["scanned_ips"], 32_768)
        self.assertEqual(model["stats"]["consulted_blacklists"], 156)
        self.assertEqual(model["stats"]["timeouts"], 18)
        self.assertEqual(model["stats"]["errors"], 2)
        self.assertEqual(model["charts"]["top_hits"][0]["name"], "zen.spamhaus.org")
        self.assertEqual(len(model["groups"]), 128)
        self.assertEqual(model["groups"][0]["block"], "186.198.128.0/24")
        self.assertEqual(model["groups"][0]["detected_count"], 24)
        self.assertEqual(model["groups"][0]["listed_percent"], 9.38)
        self.assertEqual(model["groups"][1]["listed_percent"], 0)

        rows = build_summary_block_rows(large_scan, "186.198.128.0/24")
        self.assertEqual(len(rows), 256)
        self.assertTrue(rows[0]["has_detection"])
        self.assertFalse(rows[24]["has_detection"])

    def test_positive_rows_are_compacted_by_ip_and_ignore_informational_only_hits(self) -> None:
        compact = compact_listed_ip_results([
            {"target_value": "203.0.113.1", "blacklist": "zen.spamhaus.org"},
            {"target_value": "203.0.113.1", "blacklist": "zen.spamhaus.org"},
            {"target_value": "203.0.113.2", "blacklist": "all.s5h.net"},
        ])

        self.assertEqual(compact, [["203.0.113.1", ["zen.spamhaus.org"]]])


if __name__ == "__main__":
    unittest.main()
