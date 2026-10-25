from __future__ import annotations

import os
import unittest
from unittest.mock import Mock, patch

from psycopg.errors import ConnectionTimeout

os.environ.setdefault("APP_ENV", "development")

from inh.core import CheckResult, CheckTask
from isp_health.worker import _db_call, _run_scan


class WorkerResilienceTests(unittest.TestCase):
    def test_cancellation_polling_does_not_open_a_connection_every_ten_checks(self) -> None:
        tasks = [CheckTask("dig", "ip", "203.0.113.1", f"q{i}", "test.example", "test") for i in range(100)]

        def execute(task: CheckTask) -> CheckResult:
            return CheckResult(task, "clean", [], 1)

        with patch("isp_health.worker._preflight_target"), \
             patch("isp_health.worker.build_tasks", return_value=(tasks, [], "IPv4", {"ip_targets": []})), \
             patch("isp_health.worker.determine_max_workers", return_value=1), \
             patch("isp_health.worker.execute_task", side_effect=execute), \
             patch("isp_health.worker.list_resume_results", return_value=[]), \
             patch("isp_health.worker.set_total_checks"), \
             patch("isp_health.worker.record_scan_event"), \
             patch("isp_health.worker.add_results"), \
             patch("isp_health.worker.is_canceled", return_value=False) as canceled, \
             patch("isp_health.worker.build_scan_summary"), \
             patch("isp_health.worker._summary_payload", return_value={}), \
             patch("isp_health.worker.finish_scan") as finish:
            _run_scan({"id": 42, "target": "203.0.113.1", "profile": "conservative"})

        canceled.assert_called_once_with(42)
        finish.assert_called_once()
        self.assertEqual(finish.call_args.args, (42, "succeeded"))

    def test_resume_skips_only_saved_queries_in_a_partially_scanned_ip(self) -> None:
        tasks = [CheckTask("dig", "ip", "203.0.113.1", f"q{i}", "test.example", "test") for i in range(3)]
        saved = [{"target_kind": "ip", "target_value": "203.0.113.1", "blacklist": "test.example",
                  "query_name": "q0", "status": "clean", "answers": [], "duration_ms": 1}]

        with patch("isp_health.worker._preflight_target"), \
             patch("isp_health.worker.build_tasks", return_value=(tasks, [], "IPv4", {"ip_targets": []})), \
             patch("isp_health.worker.list_resume_results", return_value=saved), \
             patch("isp_health.worker.determine_max_workers", return_value=1), \
             patch("isp_health.worker.execute_task", side_effect=lambda task: CheckResult(task, "clean", [], 1)) as execute, \
             patch("isp_health.worker.set_total_checks") as set_total, \
             patch("isp_health.worker.record_scan_event"), \
             patch("isp_health.worker.add_results") as add_results, \
             patch("isp_health.worker.is_canceled", return_value=False), \
             patch("isp_health.worker.build_scan_summary") as summary, \
             patch("isp_health.worker._summary_payload", return_value={}), \
             patch("isp_health.worker.finish_scan"):
            _run_scan({"id": 42, "target": "203.0.113.1", "profile": "conservative"})

        self.assertEqual({call.args[0].query_name for call in execute.call_args_list}, {"q1", "q2"})
        set_total.assert_called_once_with(42, 3, 1)
        self.assertEqual(len(summary.call_args.kwargs["results"]), 3)
        self.assertEqual(add_results.call_args.args[2], 3)

    def test_scan_continues_after_a_transient_database_connection_timeout(self) -> None:
        operation = Mock(side_effect=[ConnectionTimeout("connection timeout expired"), True])

        with patch("isp_health.worker.time.sleep") as sleep:
            self.assertTrue(_db_call(operation))

        self.assertEqual(operation.call_count, 2)
        sleep.assert_called_once_with(1)

    def test_scan_stops_after_repeated_database_connection_timeouts(self) -> None:
        operation = Mock(side_effect=ConnectionTimeout("connection timeout expired"))

        with patch("isp_health.worker.time.sleep") as sleep:
            with self.assertRaises(ConnectionTimeout):
                _db_call(operation)

        self.assertEqual(operation.call_count, 5)
        self.assertEqual(sleep.call_count, 4)


if __name__ == "__main__":
    unittest.main()
