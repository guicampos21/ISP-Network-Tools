from __future__ import annotations

import os
import socket
import subprocess
import unittest
from unittest.mock import patch

os.environ.setdefault("APP_ENV", "development")

from inh.core import CheckTask, build_tasks, execute_task, resolve_domain_ipv4s, run_dig
from isp_health.web import _scan_result_tag, _validate_target
from isp_health.worker import _preflight_target


class DnsblInputTests(unittest.TestCase):
    def test_dns_failure_codes_are_not_negative_listings(self):
        for status in ("SERVFAIL", "REFUSED"):
            with self.subTest(status=status), patch("inh.core.subprocess.run", return_value=subprocess.CompletedProcess([], 0, f";; ->>HEADER<<- status: {status}, id: 1\n", "")):
                self.assertEqual(run_dig("test.example"), ([], "error"))

    def test_valid_dns_answers_and_nxdomain_are_distinguished(self):
        output = ";; ->>HEADER<<- status: NOERROR, id: 1\ntest.example. 60 IN A 127.0.0.2\n"
        with patch.dict(os.environ, {"HEALTH_DNS_SERVER": "10.254.60.101"}), patch("inh.core.subprocess.run", return_value=subprocess.CompletedProcess([], 0, output, "")) as command:
            self.assertEqual(run_dig("test.example"), (["127.0.0.2"], "ok"))
            self.assertIn("@10.254.60.101", command.call_args.args[0])
        with patch("inh.core.subprocess.run", return_value=subprocess.CompletedProcess([], 0, ";; ->>HEADER<<- status: NXDOMAIN, id: 1\n", "")):
            self.assertEqual(run_dig("test.example"), ([], "ok"))

    def test_dns_no_a_record_does_not_fail_domain_scan(self) -> None:
        with patch("inh.core.socket.getaddrinfo", side_effect=socket.gaierror(socket.EAI_NONAME, "no A record")):
            self.assertEqual(resolve_domain_ipv4s("dbltest.com"), [])

    def test_standard_dnsbl_test_address_is_allowed(self) -> None:
        self.assertEqual(_validate_target("127.0.0.2"), ("ip", "127.0.0.2"))
        _preflight_target("ip", "127.0.0.2")

    def test_private_addresses_and_loopback_domains_are_still_rejected(self) -> None:
        for address in ("127.0.0.1", "127.0.0.3", "10.0.0.1"):
            with self.subTest(address=address), self.assertRaises(ValueError):
                _validate_target(address)
        with patch("isp_health.worker.resolve_domain_ipv4s", return_value=["127.0.0.2"]):
            with self.assertRaises(ValueError):
                _preflight_target("domain", "example.com")

    def test_positive_dnsbl_answer_is_detected(self) -> None:
        task = CheckTask(query_mode="dig", target_kind="ip", target_value="127.0.0.2", query_name="2.0.0.127.bl.spamcop.net", blacklist="bl.spamcop.net", label="test")
        with patch("inh.core.run_dig", return_value=(["127.0.0.2"], "ok")):
            self.assertEqual(execute_task(task).status, "listed")

    def test_domain_without_a_record_still_builds_domain_checks(self) -> None:
        with patch("inh.core.resolve_domain_ipv4s", side_effect=ValueError("no A record")):
            tasks, details, _, metadata = build_tasks("domain", "dbltest.com")

        self.assertTrue(any(task.blacklist == "dbl.spamhaus.org" for task in tasks))
        self.assertEqual(metadata["ip_targets"], [])
        self.assertIn("Nenhum registro A", " ".join(details))

    def test_spamhaus_policy_answer_is_not_a_listing(self) -> None:
        task = CheckTask(
            query_mode="dig",
            target_kind="domain",
            target_value="dbltest.com",
            query_name="dbltest.com.dbl.spamhaus.org",
            blacklist="dbl.spamhaus.org",
            label="Dominio dbltest.com",
        )
        with patch("inh.core.run_dig", return_value=(["127.255.255.254"], "ok")):
            result = execute_task(task)

        self.assertEqual(result.status, "error")
        self.assertEqual(result.answers, ["127.255.255.254"])

    def test_missing_positive_test_probe_is_inconclusive_instead_of_clean(self):
        task = CheckTask(query_mode="dig", target_kind="domain", target_value="dbltest.com", query_name="dbltest.com.dbl.spamhaus.org", blacklist="dbl.spamhaus.org", label="DBL test")
        with patch("inh.core.run_dig", return_value=([], "ok")):
            result = execute_task(task)
        self.assertEqual(result.status, "error")
        self.assertIn("alvo de teste", result.answers[0])

    def test_history_exposes_result_tag(self) -> None:
        self.assertEqual(_scan_result_tag({"status": "succeeded", "summary_json": {"unique_ips_listed": 0}}), ("Sem detecções", "clean"))
        self.assertEqual(_scan_result_tag({"status": "succeeded", "summary_json": {"unique_ips_listed": 2}}), ("2 IPs listados", "listed"))
        self.assertEqual(_scan_result_tag({"status": "succeeded", "summary_json": {"error_results": 1}}), ("Resultado incompleto", "incomplete"))


if __name__ == "__main__":
    unittest.main()
