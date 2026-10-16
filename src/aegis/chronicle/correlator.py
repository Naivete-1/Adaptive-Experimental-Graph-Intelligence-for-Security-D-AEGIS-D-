"""
Chronicle — incident correlation.

Groups alerts on the same user within a sliding time window into a
single incident. This is correlation, not causation: alerts grouped
together may or may not be related, and the incident is a container for
investigation, not a conclusion.

Design:
  * One incident per (user, time-cluster).
  * Clustering is simple gap-based: sort alerts by timestamp; a gap
    larger than `window_seconds` starts a new incident.
  * An incident is a summary of the alerts and events it contains.
"""

from datetime import datetime
from typing import Any

from aegis.sentinel.rules import RULE_SEVERITY


DEFAULT_WINDOW_SECONDS = 900  # 15 minutes

SEVERITY_ORDER = {"low": 0, "medium": 1, "high": 2}


def _parse_ts(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def _max_severity(severities: list[str]) -> str:
    return max(severities, key=lambda s: SEVERITY_ORDER.get(s, -1))


def _build_incident(
    user: str,
    alerts: list[dict[str, Any]],
    events_by_id: dict[str, dict[str, Any]],
    index: int,
) -> dict[str, Any]:
    alert_ids = [a["alert_id"] for a in alerts]
    rule_names = sorted({a["rule"] for a in alerts})
    all_event_ids = [eid for a in alerts for eid in a["event_ids"]]
    first_seen = min(a["first_seen"] for a in alerts)
    last_seen = max(a["last_seen"] for a in alerts)

    evidence_events = [
        events_by_id[eid] for eid in all_event_ids if eid in events_by_id
    ]

    return {
        "incident_id": f"INC-{index:05d}",
        "user": user,
        "status": "open",
        "first_seen": first_seen,
        "last_seen": last_seen,
        "alert_ids": alert_ids,
        "alert_count": len(alert_ids),
        "rule_names": rule_names,
        "severity": _max_severity([a["severity"] for a in alerts]),
        "confidence": round(
            max(a["confidence"] for a in alerts), 4
        ),
        "event_ids": all_event_ids,
        "event_count": len(all_event_ids),
        "events": evidence_events,
        "summary": (
            f"{len(alert_ids)} alert(s) on {user}: "
            f"{', '.join(rule_names)}"
        ),
        "correlation_note": (
            "Alerts are grouped by user and time proximity. "
            "Grouping does not establish that the alerts are related."
        ),
    }


def correlate_alerts(
    alerts: list[dict[str, Any]],
    events: list[dict[str, Any]] | None = None,
    *,
    window_seconds: int = DEFAULT_WINDOW_SECONDS,
) -> list[dict[str, Any]]:
    """
    Group alerts into incidents by user and time proximity.

    Returns a list of incident dicts, sorted by first_seen.
    """
    if not isinstance(alerts, list):
        raise ValueError("alerts must be a list")
    if events is not None and not isinstance(events, list):
        raise ValueError("events must be a list or None")
    if not isinstance(window_seconds, int) or window_seconds < 0:
        raise ValueError("window_seconds must be a non-negative integer")

    if not alerts:
        return []

    events_by_id = {e["event_id"]: e for e in (events or [])}

    # Group alerts by user.
    by_user: dict[str, list[dict[str, Any]]] = {}
    for alert in alerts:
        by_user.setdefault(alert["user"], []).append(alert)

    incidents: list[dict[str, Any]] = []
    incident_index = 1

    for user, user_alerts in by_user.items():
        user_alerts.sort(key=lambda a: a["first_seen"])

        current_cluster: list[dict[str, Any]] = []
        last_ts: datetime | None = None

        for alert in user_alerts:
            alert_ts = _parse_ts(alert["first_seen"])

            if last_ts is None or (alert_ts - last_ts).total_seconds() <= window_seconds:
                current_cluster.append(alert)
            else:
                incidents.append(_build_incident(
                    user, current_cluster, events_by_id, incident_index
                ))
                incident_index += 1
                current_cluster = [alert]

            last_ts = _parse_ts(alert["last_seen"])

        if current_cluster:
            incidents.append(_build_incident(
                user, current_cluster, events_by_id, incident_index
            ))
            incident_index += 1

    incidents.sort(key=lambda inc: inc["first_seen"])
    return incidents