from __future__ import annotations

import concurrent.futures
import ipaddress
import json
import logging
import os
import time
from typing import Any

from redis import Redis
from redis.exceptions import RedisError

from inh.core import (
    CheckResult,
    build_scan_summary,
    build_tasks,
    determine_max_workers,
    detect_target_type,
    execute_task,
    resolve_domain_ipv4s,
)

from .config import app_config
from .storage import (
    add_result,
    claim_scan,
    finish_scan,
    get_scan,
    init_schema,
    is_canceled,
    set_total_checks,
)


logging.basicConfig(
    level=os.getenv("LOG_LEVEL", "INFO").upper(),
    format="%(asctime)s %(levelname)s %(message)s",
)
CONFIG = app_config()


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
        if not _global_ipv4(value):
            raise ValueError("O alvo IPv4 não é público.")
        return
    if kind == "cidr":
        network = ipaddress.ip_network(value, strict=False)
        if network.version != 4 or not network.is_global:
            raise ValueError("O bloco CIDR não é público.")
        return
    if kind == "domain":
        addresses = resolve_domain_ipv4s(value)
        if not addresses or any(not _global_ipv4(address) for address in addresses):
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
        if not _global_ipv4(str(address)):
            raise ValueError("A coleta encontrou um destino IPv4 não público.")
    set_total_checks(scan_id, len(tasks))
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
    results: list[CheckResult] = []
    pending: dict[concurrent.futures.Future, Any] = {}
    task_iterator = iter(tasks)
    completed = 0
    queue_depth = max(1, workers * 3)

    def submit_next(executor) -> bool:
        try:
            task = next(task_iterator)
        except StopIteration:
            return False
        pending[executor.submit(execute_task, task)] = task
        return True

    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as executor:
        for _ in range(min(queue_depth, len(tasks))):
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
                add_result(scan_id, _result_payload(result), completed)
                if completed % 10 == 0 and is_canceled(scan_id):
                    finish_scan(scan_id, "canceled")
                    return
                while len(pending) < queue_depth and submit_next(executor):
                    pass

    if is_canceled(scan_id):
        finish_scan(scan_id, "canceled")
        return
    summary = build_scan_summary(
        kind=kind,
        original_input=str(scan["target"]),
        normalized_input=normalized,
        detected_mode=detected_mode,
        details=details,
        metadata=metadata,
        results=results,
    )
    finish_scan(scan_id, "succeeded", summary=_summary_payload(summary))


def process_job(client: Redis, payload: str) -> None:
    job = json.loads(payload)
    scan_id = int(job["scan_id"])
    lock_key = str(job.get("lock_key", ""))
    lock_token = str(job.get("lock_token", ""))
    try:
        if not claim_scan(scan_id):
            return
        scan = get_scan(scan_id)
        if not scan:
            return
        try:
            _run_scan(scan)
        except Exception as exc:
            logging.warning("scan=%s failed: %s", scan_id, type(exc).__name__)
            finish_scan(scan_id, "failed", error_message="A análise não pôde ser concluída.")
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
