#
# Copyright (C) 2026 Guilherme Campos
# SPDX-License-Identifier: GPL-3.0-or-later
#
from __future__ import annotations

import unittest
from types import SimpleNamespace

from inh import cli
from inh.core import CheckResult, CheckTask


def make_result(
    blacklist: str,
    *,
    status: str = "listed",
    target_kind: str = "ip",
    target_value: str = "203.0.113.10",
    query_mode: str = "dnsbl",
    answers: list[str] | None = None,
) -> CheckResult:
    return CheckResult(
        task=CheckTask(
            query_mode=query_mode,
            target_kind=target_kind,
            target_value=target_value,
            query_name="example",
            blacklist=blacklist,
            label=target_value,
        ),
        status=status,
        answers=answers or (["127.0.0.2"] if status == "listed" else []),
        duration_ms=10,
    )


class RiskLogicTests(unittest.TestCase):
    def test_same_family_high_hits_do_not_become_very_high(self) -> None:
        analysis = cli._analyze_ip_results(
            "203.0.113.10",
            [
                make_result("b.barracudacentral.org"),
                make_result("bb.barracudacentral.org"),
            ],
            [],
            [],
            [],
            [],
        )
        self.assertEqual(analysis["unique_blacklists_count"], 2)
        self.assertEqual(analysis["unique_families_count"], 1)
        self.assertEqual(analysis["risk_level"], "high")

    def test_independent_high_families_become_very_high(self) -> None:
        analysis = cli._analyze_ip_results(
            "203.0.113.10",
            [
                make_result("b.barracudacentral.org"),
                make_result("bl.spamcop.net"),
            ],
            [],
            [],
            [],
            [],
        )
        self.assertEqual(analysis["unique_blacklists_count"], 2)
        self.assertEqual(analysis["unique_families_count"], 2)
        self.assertEqual(analysis["risk_level"], "very_high")

    def test_spamhaus_zen_is_very_high(self) -> None:
        analysis = cli._analyze_ip_results(
            "203.0.113.10",
            [make_result("zen.spamhaus.org")],
            [],
            [],
            [],
            [],
        )
        self.assertEqual(analysis["risk_level"], "very_high")

    def test_informational_only_is_informational(self) -> None:
        analysis = cli._analyze_ip_results(
            "203.0.113.10",
            [],
            [],
            [make_result("hostkarma.junkemailfilter.com")],
            [],
            [],
        )
        self.assertEqual(analysis["risk_level"], "informational")
        self.assertEqual(analysis["direct_hits_count"], 0)

    def test_timeout_without_hit_is_timeout(self) -> None:
        analysis = cli._analyze_ip_results(
            "203.0.113.10",
            [],
            [],
            [],
            [make_result("bl.spamcop.net", status="timeout")],
            [],
        )
        self.assertEqual(analysis["risk_level"], "timeout")
        self.assertEqual(analysis["dnsbl_occurrences_count"], 0)

    def test_report_with_asn_drop_is_very_high(self) -> None:
        summary = SimpleNamespace(
            inventory_rows=[],
            unique_ips_scanned=0,
            asn_drop_listed=True,
            network_scope_listed=False,
            timeout_results=0,
            error_results=0,
            total_checks=1,
        )
        report = cli._analyze_report_risk(summary, [])
        self.assertEqual(report["report_risk_level"], "very_high")

    def test_barracuda_concentrated_report_is_high(self) -> None:
        rows = []
        for last_octet in range(1, 8):
            rows.append(
                cli._analyze_ip_results(
                    f"198.51.100.{last_octet}",
                    [
                        make_result("b.barracudacentral.org", target_value=f"198.51.100.{last_octet}"),
                        make_result("bb.barracudacentral.org", target_value=f"198.51.100.{last_octet}"),
                    ],
                    [],
                    [],
                    [],
                    [],
                )
            )
        summary = SimpleNamespace(
            inventory_rows=rows,
            unique_ips_scanned=32,
            asn_drop_listed=False,
            network_scope_listed=False,
            timeout_results=0,
            error_results=0,
            total_checks=100,
        )
        report = cli._analyze_report_risk(summary, [])
        self.assertEqual(report["report_risk_level"], "high")
        self.assertEqual(report["report_confidence"], "medium_high")
        self.assertIn("Barracuda", " ".join(report["report_risk_reason"]))

    def test_report_without_relevant_hits_is_none(self) -> None:
        summary = SimpleNamespace(
            inventory_rows=[
                {
                    "ip": "203.0.113.10",
                    "status": "clean",
                    "relevant": [],
                    "informational": [],
                    "direct_hits_count": 0,
                    "network_hits_count": 0,
                    "informational_hits_count": 0,
                    "dnsbl_occurrences_count": 0,
                    "affected_families": [],
                    "affected_family_keys": [],
                }
            ],
            unique_ips_scanned=1,
            asn_drop_listed=False,
            network_scope_listed=False,
            timeout_results=0,
            error_results=0,
            total_checks=10,
        )
        report = cli._analyze_report_risk(summary, [])
        self.assertEqual(report["report_risk_level"], "none")
        self.assertIn("Sem risco", " ".join(report["report_risk_reason"]))


if __name__ == "__main__":
    unittest.main()
