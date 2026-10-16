"""
Event schema and validation.

An event is a low-level telemetry record: a single observed action by an
identity, at a time, from a source. Detection operates on events; it does
not know about scenarios or incidents. That separation is deliberate.
"""

from typing import Any


EVENT_TYPES = (
    "login_attempt",
    "role_assignment",
    "data_download",
)

REQUIRED_FIELDS = (
    "event_id",
    "timestamp",     # ISO 8601 UTC, e.g. "2026-01-01T12:00:00Z"
    "event_type",
    "user",
    "source_ip",
)


def validate_event(event: dict[str, Any]) -> None:
    """Raise ValueError if the event is not well-formed."""
    if not isinstance(event, dict):
        raise ValueError("event must be a dictionary")

    for field in REQUIRED_FIELDS:
        if field not in event:
            raise ValueError(f"event missing required field: {field}")

    if event["event_type"] not in EVENT_TYPES:
        raise ValueError(f"unknown event_type: {event['event_type']!r}")

    if event["event_type"] == "login_attempt":
        if "success" not in event or not isinstance(event["success"], bool):
            raise ValueError("login_attempt requires boolean 'success'")

    if event["event_type"] == "role_assignment":
        if not isinstance(event.get("role"), str) or not event["role"]:
            raise ValueError("role_assignment requires non-empty 'role'")

    if event["event_type"] == "data_download":
        records = event.get("records")
        if not isinstance(records, int) or isinstance(records, bool) or records < 0:
            raise ValueError("data_download requires non-negative integer 'records'")