"""CLI output formatting helpers for commands."""

from __future__ import annotations

from datetime import UTC, datetime


def utc_now_iso() -> str:
    return datetime.now(UTC).isoformat()


def print_submit_response(response: dict) -> None:
    submission_id = response.get("id", "")
    status = response.get("status", "")
    event_count = response.get("event_count")
    if event_count is None:
        print(f"submission_id={submission_id} status={status}")
    else:
        print(f"submission_id={submission_id} status={status} event_count={event_count}")
