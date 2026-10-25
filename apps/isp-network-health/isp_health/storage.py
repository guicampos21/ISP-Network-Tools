from __future__ import annotations

from typing import Any

import psycopg
from psycopg.rows import dict_row
from psycopg.types.json import Jsonb

from .config import database_url


SCHEMA = """
CREATE TABLE IF NOT EXISTS health_scans (
    id BIGSERIAL PRIMARY KEY,
    requester_subject VARCHAR(128) NOT NULL,
    requester_email VARCHAR(254) NOT NULL,
    target VARCHAR(253) NOT NULL,
    target_kind VARCHAR(16) NOT NULL,
    profile VARCHAR(16) NOT NULL,
    status VARCHAR(16) NOT NULL CHECK (status IN ('queued', 'running', 'succeeded', 'failed', 'canceled')),
    total_checks INTEGER NOT NULL DEFAULT 0,
    completed_checks INTEGER NOT NULL DEFAULT 0,
    resume_baseline INTEGER NOT NULL DEFAULT 0,
    summary_json JSONB,
    error_message VARCHAR(1000) NOT NULL DEFAULT '',
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    started_at TIMESTAMPTZ,
    finished_at TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS ix_health_scans_requester_created
    ON health_scans (requester_subject, created_at DESC);
CREATE TABLE IF NOT EXISTS health_scan_results (
    id BIGSERIAL PRIMARY KEY,
    scan_id BIGINT NOT NULL REFERENCES health_scans(id) ON DELETE CASCADE,
    target_kind VARCHAR(16) NOT NULL,
    target_value VARCHAR(253) NOT NULL,
    blacklist VARCHAR(160) NOT NULL,
    query_name VARCHAR(512) NOT NULL,
    status VARCHAR(24) NOT NULL,
    answers JSONB NOT NULL DEFAULT '[]'::jsonb,
    duration_ms INTEGER NOT NULL DEFAULT 0,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS ix_health_scan_results_scan
    ON health_scan_results (scan_id, id);
CREATE TABLE IF NOT EXISTS health_scan_events (
    id BIGSERIAL PRIMARY KEY,
    scan_id BIGINT NOT NULL REFERENCES health_scans(id) ON DELETE CASCADE,
    event_type VARCHAR(40) NOT NULL,
    details JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS ix_health_scan_events_scan_created
    ON health_scan_events (scan_id, created_at DESC, id DESC);
CREATE TABLE IF NOT EXISTS health_audit_logs (
    id BIGSERIAL PRIMARY KEY,
    actor_subject VARCHAR(128) NOT NULL DEFAULT '',
    actor_email VARCHAR(254) NOT NULL DEFAULT '',
    action VARCHAR(80) NOT NULL,
    entity_type VARCHAR(80) NOT NULL DEFAULT '',
    entity_id VARCHAR(80) NOT NULL DEFAULT '',
    details JSONB NOT NULL DEFAULT '{}'::jsonb,
    source_ip VARCHAR(64) NOT NULL DEFAULT '',
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS ix_health_audit_logs_created
    ON health_audit_logs (created_at DESC);
ALTER TABLE health_scans ADD COLUMN IF NOT EXISTS resume_baseline INTEGER NOT NULL DEFAULT 0;
"""


def connect():
    return psycopg.connect(database_url(), connect_timeout=5, row_factory=dict_row)


def init_schema() -> None:
    with connect() as connection:
        connection.execute(SCHEMA)


def create_scan(
    subject: str,
    email: str,
    target: str,
    target_kind: str,
    profile: str,
    source_ip: str = "",
    actor_subject: str | None = None,
    actor_email: str | None = None,
) -> int:
    with connect() as connection:
        row = connection.execute(
            """
            INSERT INTO health_scans
                (requester_subject, requester_email, target, target_kind, profile, status)
            VALUES (%s, %s, %s, %s, %s, 'queued')
            RETURNING id
            """,
            (subject, email, target, target_kind, profile),
        ).fetchone()
        scan_id = int(row["id"])
        connection.execute(
            "INSERT INTO health_scan_events (scan_id, event_type, details) VALUES (%s, %s, %s)",
            (
                scan_id,
                "queued",
                Jsonb({"profile": profile, "message": "Análise enfileirada. Aguardando o worker."}),
            ),
        )
        connection.execute(
            """
            INSERT INTO health_audit_logs
                (actor_subject, actor_email, action, entity_type, entity_id, details, source_ip)
            VALUES (%s, %s, %s, %s, %s, %s, %s)
            """,
            (
                (actor_subject or subject)[:128], (actor_email or email)[:254], "scan.created", "scan", str(scan_id),
                Jsonb({"target": str(target)[:253], "profile": profile, "owner_email": email[:254]}), str(source_ip)[:64],
            ),
        )
        return scan_id


def get_scan(scan_id: int, subject: str | None = None) -> dict[str, Any] | None:
    query = "SELECT * FROM health_scans WHERE id = %s"
    params: list[Any] = [scan_id]
    if subject is not None:
        query += " AND requester_subject = %s"
        params.append(subject)
    with connect() as connection:
        return connection.execute(query, params).fetchone()


def list_scans(subject: str, limit: int = 40) -> list[dict[str, Any]]:
    with connect() as connection:
        return list(
            connection.execute(
                """
                SELECT * FROM health_scans
                WHERE requester_subject = %s
                ORDER BY created_at DESC
                LIMIT %s
                """,
                (subject, max(1, min(limit, 100))),
            ).fetchall()
        )


def list_all_scans(*, subject: str | None = None, limit: int = 50, offset: int = 0) -> tuple[list[dict[str, Any]], int]:
    where = "WHERE requester_subject = %s" if subject else ""
    params: tuple[Any, ...] = (subject,) if subject else ()
    with connect() as connection:
        total = int(connection.execute(f"SELECT count(*) AS total FROM health_scans {where}", params).fetchone()["total"])
        rows = connection.execute(
            f"SELECT * FROM health_scans {where} ORDER BY created_at DESC, id DESC LIMIT %s OFFSET %s",
            (*params, max(1, min(limit, 100)), max(0, offset)),
        ).fetchall()
        return list(rows), total


def list_active_scans_for_admin(limit: int = 100) -> list[dict[str, Any]]:
    """Return only queued/running scans for the private Admin Center feed."""
    with connect() as connection:
        return list(
            connection.execute(
                """
                SELECT * FROM health_scans
                WHERE status IN ('queued', 'running')
                ORDER BY created_at ASC
                LIMIT %s
                """,
                (max(1, min(limit, 100)),),
            ).fetchall()
        )


def list_results(scan_id: int) -> list[dict[str, Any]]:
    with connect() as connection:
        return list(
            connection.execute(
                "SELECT * FROM health_scan_results WHERE scan_id = %s ORDER BY id",
                (scan_id,),
            ).fetchall()
        )


def list_listed_ip_results(scan_id: int) -> list[dict[str, Any]]:
    """Return only positive IP hits for compact report backfills."""
    with connect() as connection:
        return list(
            connection.execute(
                """SELECT target_value, blacklist
                   FROM health_scan_results
                   WHERE scan_id = %s AND target_kind = 'ip' AND status = 'listed'
                   ORDER BY target_value, blacklist""",
                (scan_id,),
            ).fetchall()
        )


def cache_scan_listed_ips(scan_id: int, listed_ips: list[list[Any]]) -> None:
    """Persist the bounded positive-hit inventory used by large reports."""
    with connect() as connection:
        connection.execute(
            """UPDATE health_scans
               SET summary_json = jsonb_set(COALESCE(summary_json, '{}'::jsonb), '{listed_ips}', %s, true)
               WHERE id = %s""",
            (Jsonb(listed_ips), scan_id),
        )


def list_recent_results(scan_id: int, limit: int = 50) -> list[dict[str, Any]]:
    """Return a bounded preview for live monitoring without loading the scan history."""
    with connect() as connection:
        rows = connection.execute(
            """SELECT target_value, blacklist, status, answers
               FROM health_scan_results
               WHERE scan_id = %s ORDER BY id DESC LIMIT %s""",
            (scan_id, max(1, min(limit, 100))),
        ).fetchall()
        return list(reversed(rows))


def list_resume_results(scan_id: int) -> list[dict[str, Any]]:
    with connect() as connection:
        return list(connection.execute(
            """SELECT target_kind, target_value, blacklist, query_name, status, answers, duration_ms
               FROM health_scan_results WHERE scan_id = %s ORDER BY id""",
            (scan_id,),
        ).fetchall())


def requeue_scan(scan_id: int, owner_subject: str | None, actor_subject: str, actor_email: str, source_ip: str = "") -> dict[str, Any] | None:
    """Atomically queue a stopped scan while preserving its committed results."""
    with connect() as connection:
        row = connection.execute(
            """UPDATE health_scans SET status = 'queued', started_at = NULL, finished_at = NULL,
                   summary_json = NULL, error_message = '',
                   completed_checks = (SELECT count(*) FROM health_scan_results WHERE scan_id = %s),
                   resume_baseline = (SELECT count(*) FROM health_scan_results WHERE scan_id = %s)
               WHERE id = %s AND status IN ('failed', 'canceled')
                 AND (%s::varchar IS NULL OR requester_subject = %s)
               RETURNING *""",
            (scan_id, scan_id, scan_id, owner_subject, owner_subject),
        ).fetchone()
        if not row:
            return None
        connection.execute(
            "INSERT INTO health_scan_events (scan_id, event_type, details) VALUES (%s, 'resumed', %s)",
            (scan_id, Jsonb({"message": f"Análise retomada: {row['completed_checks']} consultas concluídas serão preservadas.", "completed_checks": row["completed_checks"]})),
        )
        connection.execute(
            """INSERT INTO health_audit_logs
               (actor_subject, actor_email, action, entity_type, entity_id, details, source_ip)
               VALUES (%s, %s, 'scan.resumed', 'scan', %s, %s, %s)""",
            (actor_subject[:128], actor_email[:254], str(scan_id),
             Jsonb({"owner_email": row["requester_email"], "completed_checks": row["completed_checks"]}), source_ip[:64]),
        )
        return dict(row)


def list_scan_events(scan_id: int, limit: int = 40) -> list[dict[str, Any]]:
    """Return the newest bounded window in chronological display order."""
    with connect() as connection:
        rows = list(
            connection.execute(
                """
                SELECT * FROM health_scan_events
                WHERE scan_id = %s
                ORDER BY created_at DESC, id DESC
                LIMIT %s
                """,
                (scan_id, max(1, min(limit, 100))),
            ).fetchall()
        )
        return list(reversed(rows))


def list_recent_scans(subject: str | None = None, limit: int = 6) -> list[dict[str, Any]]:
    query = "SELECT * FROM health_scans"
    params: list[Any] = []
    if subject is not None:
        query += " WHERE requester_subject = %s"
        params.append(subject)
    query += " ORDER BY created_at DESC, id DESC LIMIT %s"
    params.append(max(1, min(limit, 40)))
    with connect() as connection:
        return list(connection.execute(query, params).fetchall())


def record_scan_event(scan_id: int, event_type: str, details: dict[str, Any] | None = None) -> None:
    with connect() as connection:
        connection.execute(
            "INSERT INTO health_scan_events (scan_id, event_type, details) VALUES (%s, %s, %s)",
            (scan_id, event_type[:40], Jsonb(details or {})),
        )


def claim_scan(scan_id: int) -> bool:
    with connect() as connection:
        row = connection.execute(
            """
            UPDATE health_scans
            SET status = 'running', started_at = now()
            WHERE id = %s AND status = 'queued'
            RETURNING id
            """,
            (scan_id,),
        ).fetchone()
        if not row:
            return False
        connection.execute(
            "INSERT INTO health_scan_events (scan_id, event_type, details) VALUES (%s, %s, %s)",
            (scan_id, "started", Jsonb({"message": "Worker iniciou a análise."})),
        )
        return True


def is_canceled(scan_id: int) -> bool:
    with connect() as connection:
        row = connection.execute(
            "SELECT status FROM health_scans WHERE id = %s", (scan_id,)
        ).fetchone()
        return bool(row and row["status"] == "canceled")


def cancel_scan(scan_id: int, subject: str | None, *, actor_subject: str = "", actor_email: str = "") -> bool:
    with connect() as connection:
        row = connection.execute(
            """
            UPDATE health_scans
            SET status = 'canceled', finished_at = now()
            WHERE id = %s AND (%s::varchar IS NULL OR requester_subject = %s)
              AND status IN ('queued', 'running')
            RETURNING id
            """,
            (scan_id, subject, subject),
        ).fetchone()
        if not row:
            return False
        connection.execute(
            "INSERT INTO health_scan_events (scan_id, event_type, details) VALUES (%s, %s, %s)",
            (scan_id, "canceled", Jsonb({"message": "Cancelamento solicitado pelo usuário."})),
        )
        connection.execute(
            """
            INSERT INTO health_audit_logs
                (actor_subject, actor_email, action, entity_type, entity_id, details)
            SELECT %s, %s, %s, %s, %s, %s
            FROM health_scans WHERE id = %s
            """,
            (actor_subject or subject or "", actor_email, "scan.canceled", "scan", str(scan_id), Jsonb({}), scan_id),
        )
        return True


def delete_scan(scan_id: int, subject: str, source_ip: str = "") -> bool:
    """Delete a completed scan owned by the requester and retain an audit event."""
    with connect() as connection:
        scan = connection.execute(
            """
            SELECT requester_subject, requester_email, target, status
            FROM health_scans
            WHERE id = %s AND requester_subject = %s
            FOR UPDATE
            """,
            (scan_id, subject),
        ).fetchone()
        if not scan or scan["status"] not in {"succeeded", "failed", "canceled"}:
            return False
        connection.execute(
            """
            INSERT INTO health_audit_logs
                (actor_subject, actor_email, action, entity_type, entity_id, details, source_ip)
            VALUES (%s, %s, %s, %s, %s, %s, %s)
            """,
            (
                scan["requester_subject"][:128],
                scan["requester_email"][:254],
                "scan.deleted",
                "scan",
                str(scan_id),
                Jsonb({"target": str(scan["target"])[:253], "status": scan["status"]}),
                str(source_ip)[:64],
            ),
        )
        connection.execute("DELETE FROM health_scans WHERE id = %s", (scan_id,))
        return True


def list_audit_logs(limit: int = 500) -> list[dict[str, Any]]:
    with connect() as connection:
        return list(
            connection.execute(
                "SELECT * FROM health_audit_logs ORDER BY created_at DESC LIMIT %s",
                (max(1, min(limit, 500)),),
            ).fetchall()
        )


def add_results(scan_id: int, results: list[dict[str, Any]], completed: int) -> None:
    if not results:
        return
    with connect() as connection:
        with connection.cursor() as cursor:
            cursor.executemany(
                """
                INSERT INTO health_scan_results
                    (scan_id, target_kind, target_value, blacklist, query_name, status, answers, duration_ms)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                """,
                [
                    (
                        scan_id,
                        result["target_kind"],
                        result["target_value"],
                        result["blacklist"],
                        result["query_name"],
                        result["status"],
                        Jsonb(result.get("answers", [])),
                        int(result.get("duration_ms", 0)),
                    )
                    for result in results
                ],
            )
        connection.execute(
            "UPDATE health_scans SET completed_checks = %s WHERE id = %s",
            (completed, scan_id),
        )


def add_result(scan_id: int, result: dict[str, Any], completed: int) -> None:
    add_results(scan_id, [result], completed)


def set_total_checks(scan_id: int, total: int, completed: int = 0) -> None:
    with connect() as connection:
        connection.execute(
            "UPDATE health_scans SET total_checks = %s, completed_checks = %s WHERE id = %s",
            (total, completed, scan_id),
        )


def finish_scan(
    scan_id: int,
    status: str,
    *,
    summary: dict[str, Any] | None = None,
    error_message: str = "",
) -> None:
    with connect() as connection:
        row = connection.execute(
            """
            UPDATE health_scans
            SET status = %s, summary_json = %s, error_message = %s, finished_at = now()
            WHERE id = %s AND (
                (status = 'running' AND %s IN ('succeeded', 'failed'))
                OR (status = 'queued' AND %s = 'failed')
            )
            RETURNING id
            """,
            (status, Jsonb(summary) if summary is not None else None, error_message[:1000], scan_id, status, status),
        ).fetchone()
        if not row:
            return
        connection.execute(
            "INSERT INTO health_scan_events (scan_id, event_type, details) VALUES (%s, %s, %s)",
            (
                scan_id,
                status,
                Jsonb(
                    {
                        "message": {
                            "succeeded": "Análise concluída.",
                            "failed": "A análise foi encerrada com erro.",
                            "canceled": "A análise foi cancelada.",
                        }.get(status, "Análise encerrada."),
                        **({"error": error_message[:200]} if error_message else {}),
                    }
                ),
            ),
        )
