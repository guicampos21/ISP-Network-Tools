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
            (scan_id, "queued", Jsonb({"profile": profile})),
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
            "INSERT INTO health_scan_events (scan_id, event_type) VALUES (%s, %s)",
            (scan_id, "started"),
        )
        return True


def is_canceled(scan_id: int) -> bool:
    with connect() as connection:
        row = connection.execute(
            "SELECT status FROM health_scans WHERE id = %s", (scan_id,)
        ).fetchone()
        return bool(row and row["status"] == "canceled")


def cancel_scan(scan_id: int, subject: str) -> bool:
    with connect() as connection:
        row = connection.execute(
            """
            UPDATE health_scans
            SET status = 'canceled', finished_at = now()
            WHERE id = %s AND requester_subject = %s
              AND status IN ('queued', 'running')
            RETURNING id
            """,
            (scan_id, subject),
        ).fetchone()
        if not row:
            return False
        connection.execute(
            "INSERT INTO health_scan_events (scan_id, event_type) VALUES (%s, %s)",
            (scan_id, "canceled"),
        )
        return True


def add_result(scan_id: int, result: dict[str, Any], completed: int) -> None:
    with connect() as connection:
        connection.execute(
            """
            INSERT INTO health_scan_results
                (scan_id, target_kind, target_value, blacklist, query_name, status, answers, duration_ms)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
            """,
            (
                scan_id,
                result["target_kind"],
                result["target_value"],
                result["blacklist"],
                result["query_name"],
                result["status"],
                Jsonb(result.get("answers", [])),
                int(result.get("duration_ms", 0)),
            ),
        )
        connection.execute(
            "UPDATE health_scans SET completed_checks = %s WHERE id = %s",
            (completed, scan_id),
        )


def set_total_checks(scan_id: int, total: int) -> None:
    with connect() as connection:
        connection.execute(
            "UPDATE health_scans SET total_checks = %s WHERE id = %s",
            (total, scan_id),
        )


def finish_scan(
    scan_id: int,
    status: str,
    *,
    summary: dict[str, Any] | None = None,
    error_message: str = "",
) -> None:
    with connect() as connection:
        connection.execute(
            """
            UPDATE health_scans
            SET status = %s, summary_json = %s, error_message = %s, finished_at = now()
            WHERE id = %s
            """,
            (status, Jsonb(summary) if summary is not None else None, error_message[:1000], scan_id),
        )
        connection.execute(
            "INSERT INTO health_scan_events (scan_id, event_type, details) VALUES (%s, %s, %s)",
            (scan_id, status, Jsonb({"error": error_message[:200]} if error_message else {})),
        )
