from __future__ import annotations

import concurrent.futures
import ipaddress
import json
import logging
import os
import time
from typing import Any, Callable, TypeVar

from psycopg.errors import ConnectionTimeout
from redis import Redis
from redis.exceptions import RedisError

from inh.core import (
    CheckResult,
    build_scan_summary,
    build_tasks,
    determine_max_workers,
    detect_target_type,
    execute_task,
    is_dnsbl_test_ipv4,
    resolve_domain_ipv4s,
)

from .config import app_config
from .storage import (
    add_result,
    add_results,
    claim_scan,
    finish_scan,
    get_scan,
    init_schema,
    is_canceled,
    list_resume_results,
    record_scan_event,
    set_total_checks,
)


logging.basicConfig(
    level=os.getenv("LOG_LEVEL", "INFO").upper(),
    format="%(asctime)s %(levelname)s %(message)s",
)
CONFIG = app_config()
RESULT_BATCH_SIZE = 250
CANCEL_CHECK_INTERVAL_SECONDS = 5
DB_RETRY_DELAYS = (1, 2, 4, 8)
T = TypeVar("T")


def _db_call(operation: Callable[[], T]) -> T:
    """Survive a brief PostgreSQL connection stall without discarding a long scan."""
    for attempt, delay in enumerate((*DB_RETRY_DELAYS, 0), start=1):
        try:
            return operation()
        except ConnectionTimeout:
            if not delay:
                raise
            logging.warning("database connection timed out; retrying in %ss (attempt %s)", delay, attempt)
            time.sleep(delay)
    raise AssertionError("unreachable")


def _failure_message(exc: Exception) -> str:
    name = type(exc).__name__.lower()
    if "timeout" in name or "connection" in name or "operational" in name:
        return "A análise foi interrompida por uma falha de comunicação com o banco de dados."
    if isinstance(exc, ValueError):
        return str(exc)[:1000] or "A análise recebeu dados inválidos."
    return "A análise não pôde ser concluída."


def _redis() -> Redis:
    return Redis.from_url(
        str(CONFIG["REDIS_URL"]),
        decode_responses=True,
        socket_connect_timeout=2,
        # Keep the socket timeout above BRPOP's five-second blocking window.
        # Otherwise an idle but healthy queue is reported as a Redis failure.
        socket_timeout=10,
    )


def _release_lock(client: Redis, key: str, token: str) -> None:
    client.eval(
        "if redis.call('get', KEYS[1]) == ARGV[1] then return redis.call('del', KEYS[1]) else return 0 end",
        1,
        key,
        token,
    )


def _global_ipv4(value: str) -> bool:
    address = ipaddress.ip_address(value)
    return address.version == 4 and address.is_global


def _preflight_target(kind: str, value: str) -> None:
    """Reject private destinations before the INH collector performs lookups."""
    if kind == "ip":
        if not (_global_ipv4(value) or is_dnsbl_test_ipv4(value)):
            raise ValueError("O alvo IPv4 não é público nem o endereço de teste DNSBL permitido.")
        return
    if kind == "cidr":
        network = ipaddress.ip_network(value, strict=False)
        if network.version != 4 or not network.is_global:
            raise ValueError("O bloco CIDR não é público.")
        return
    if kind == "domain":
        try:
            addresses = resolve_domain_ipv4s(value)
        except ValueError:
            # DBL/RHSBL checks can operate on a domain with no A record.
            return
        if any(not _global_ipv4(address) for address in addresses):
            raise ValueError("O domínio resolve para um endereço não público.")


def _result_payload(result: CheckResult) -> dict[str, Any]:
    return {
        "target_kind": result.task.target_kind,
        "target_value": result.task.target_value,
        "blacklist": result.task.blacklist,
        "query_name": result.task.query_name,
        "status": result.status,
        "answers": list(result.answers),
        "duration_ms": result.duration_ms,
    }


def _summary_payload(summary) -> dict[str, Any]:
    return {
        "kind": summary.kind,
        "normalized_input": summary.normalized_input,
        "detected_mode": summary.detected_mode,
        "risk_level": summary.risk_level,
        "total_checks": summary.total_checks,
        "listed_results": summary.listed_results,
        "unique_ips_scanned": summary.unique_ips_scanned,
        "unique_ips_listed": summary.unique_ips_listed,
        "unique_ips_clean": summary.unique_ips_clean,
        "timeout_results": summary.timeout_results,
        "error_results": summary.error_results,
        "unique_blacklists_hit": summary.unique_blacklists_hit,
        "top_blacklists": [list(item) for item in summary.top_blacklists],
        "critical_findings": list(summary.critical_findings),
        "prefix_summaries": list(summary.prefix_summaries),
        "listed_ips": [
            [str(row["ip"]), list(row["relevant"])]
            for row in summary.inventory_rows
            if row.get("relevant")
        ],
        "primary_asn": summary.primary_asn,
        "primary_holder": summary.primary_holder,
        "primary_prefix": summary.primary_prefix,
        "asn_drop_listed": summary.asn_drop_listed,
    }


def _run_scan(scan: dict[str, Any]) -> None:
    scan_id = int(scan["id"])
    kind, normalized = detect_target_type(str(scan["target"]))
    _preflight_target(kind, normalized)
    tasks, details, detected_mode, metadata = build_tasks(kind, normalized)
    for address in metadata.get("ip_targets", []):
        if not (_global_ipv4(str(address)) or (kind == "ip" and is_dnsbl_test_ipv4(str(address)))):
            raise ValueError("A coleta encontrou um destino IPv4 não público.")
    saved_rows = _db_call(lambda: list_resume_results(scan_id))
    saved_by_query = {
        (row["target_kind"], row["target_value"], row["blacklist"], row["query_name"]): row
        for row in saved_rows
    }
    results: list[CheckResult] = []
    pending_tasks = []
    for task in tasks:
        row = saved_by_query.pop((task.target_kind, task.target_value, task.blacklist, task.query_name), None)
        if row is None:
            pending_tasks.append(task)
        else:
            results.append(CheckResult(task=task, status=row["status"], answers=row["answers"] or [], duration_ms=row["duration_ms"]))
    completed = len(results)
    _db_call(lambda: set_total_checks(scan_id, len(tasks), completed))
    requested_workers = int(os.getenv("HEALTH_WORKER_WORKERS", "0"))
    maximum = int(CONFIG["HEALTH_WORKER_MAX_WORKERS"])
    workers = min(
        maximum,
        determine_max_workers(
            len(tasks),
            requested_workers,
            str(scan["profile"]) == "aggressive",
        ),
    )
    _db_call(lambda: record_scan_event(
        scan_id,
        "prepared",
        {
            "message": f"Alvo preparado: {len(tasks)} consultas; {completed} já concluídas e preservadas; {len(pending_tasks)} pendentes em {workers} workers.",
            "total_checks": len(tasks),
            "completed_checks": completed,
            "workers": workers,
        },
    ))
    result_batch: list[dict[str, Any]] = []
    pending: dict[concurrent.futures.Future, Any] = {}
    task_iterator = iter(pending_tasks)
    progress_event_interval = max(10, min(500, len(tasks) // 25 or 1))
    last_progress_event = 0
    last_cancel_check = time.monotonic()
    queue_depth = max(1, workers * 3)

    def submit_next(executor) -> bool:
        try:
            task = next(task_iterator)
        except StopIteration:
            return False
        pending[executor.submit(execute_task, task)] = task
        return True

    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as executor:
        for _ in range(min(queue_depth, len(pending_tasks))):
            submit_next(executor)
        while pending:
            done, _ = concurrent.futures.wait(
                pending,
                return_when=concurrent.futures.FIRST_COMPLETED,
            )
            for future in done:
                task = pending.pop(future)
                try:
                    result = future.result()
                except Exception as exc:
                    logging.warning("scan=%s task failed: %s", scan_id, type(exc).__name__)
                    result = CheckResult(task=task, status="error", answers=[], duration_ms=0)
                results.append(result)
                completed += 1
                result_batch.append(_result_payload(result))
                if len(result_batch) >= RESULT_BATCH_SIZE:
                    _db_call(lambda: add_results(scan_id, result_batch, completed))
                    result_batch.clear()
                if (
                    completed == 1
                    or completed == len(tasks)
                    or completed - last_progress_event >= progress_event_interval
                ):
                    _db_call(lambda: record_scan_event(
                        scan_id,
                        "progress",
                        {
                            "message": f"Consultas concluídas: {completed} de {len(tasks)}.",
                            "completed_checks": completed,
                            "total_checks": len(tasks),
                        },
                    ))
                    last_progress_event = completed
                if time.monotonic() - last_cancel_check >= CANCEL_CHECK_INTERVAL_SECONDS:
                    if _db_call(lambda: is_canceled(scan_id)):
                        if result_batch:
                            _db_call(lambda: add_results(scan_id, result_batch, completed))
                        _db_call(lambda: finish_scan(scan_id, "canceled"))
                        return
                    last_cancel_check = time.monotonic()
                while len(pending) < queue_depth and submit_next(executor):
                    pass

    if _db_call(lambda: is_canceled(scan_id)):
        if result_batch:
            _db_call(lambda: add_results(scan_id, result_batch, completed))
        _db_call(lambda: finish_scan(scan_id, "canceled"))
        return
    if result_batch:
        _db_call(lambda: add_results(scan_id, result_batch, completed))
    summary = build_scan_summary(
        kind=kind,
        original_input=str(scan["target"]),
        normalized_input=normalized,
        detected_mode=detected_mode,
        details=details,
        metadata=metadata,
        results=results,
    )
    _db_call(lambda: finish_scan(scan_id, "succeeded", summary=_summary_payload(summary)))


def process_job(client: Redis, payload: str) -> None:
    job = json.loads(payload)
    scan_id = int(job["scan_id"])
    lock_key = str(job.get("lock_key", ""))
    lock_token = str(job.get("lock_token", ""))
    try:
        if not _db_call(lambda: claim_scan(scan_id)):
            return
        scan = _db_call(lambda: get_scan(scan_id))
        if not scan:
            return
        try:
            _run_scan(scan)
        except Exception as exc:
            logging.exception("scan=%s failed: %s", scan_id, type(exc).__name__)
            _db_call(lambda: finish_scan(scan_id, "failed", error_message=_failure_message(exc)))
    finally:
        if lock_key and lock_token:
            try:
                _release_lock(client, lock_key, lock_token)
            except RedisError:
                logging.warning("scan=%s lock release failed", scan_id)


def main() -> None:
    logging.info("ISP Network Health worker started")
    init_schema()
    client = _redis()
    while True:
        try:
            item = client.brpop("health:scan:queue", timeout=5)
            if item:
                process_job(client, item[1])
        except (RedisError, OSError) as exc:
            logging.warning("health worker unavailable: %s", type(exc).__name__)
            time.sleep(3)


if __name__ == "__main__":
    main()
