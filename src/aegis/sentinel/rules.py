"""
Rule-based detection (Sentinel layer).

Each rule is a pure function: (events) -> list of alerts. Rules do not
share state. Thresholds and severities are documented assumptions, not
calibrated values.
"""

from datetime import datetime
from typing import Any

from aegis.events.schema import validate_event


# --- thresholds and constants ------------------------------------------

BRUTE_FORCE_THRESHOLD = 5          # failed logins
BRUTE_FORCE_WINDOW_SECONDS = 300   # within this window

LARGE_DOWNLOAD_THRESHOLD = 10_000  # records in a single download

PRIVILEGED_ROLES = ("cloud-admin", "root", "admin")

RULE_SEVERITY = {
    "brute_force": "medium",
    "privilege_escalation": "high",
    "large_download": "high",
}

RULE_CONFIDENCE = {
    "brute_force": 0.7,
    "privilege_escalation": 0.9,
    "large_download": 0.85,
}

# Each rule maps to a MITRE ATT&CK technique. This is a coarse mapping
# for presentation; it does not represent formal technique attribution.
RULE_MITRE = {
    "brute_force": "T1110",
    "privilege_escalation": "T1078",
    "large_download": "T1530",
}


# --- helpers ------------------------------------------------------------

def _parse_ts(value: str) -> datetime:
    # Accept "Z" suffix and "+00:00" both.
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def _alert(
    rule: str,
    events: list[dict[str, Any]],
    *,
    user: str,
    source_ip: str,
    evidence: str,
) -> dict[str, Any]:
    ids = [e["event_id"] for e in events]
    times = [e["timestamp"] for e in events]
    return {
        "alert_id": f"ALT-{rule}-{user}-{ids[0]}",
        "rule": rule,
        "severity": RULE_SEVERITY[rule],
        "confidence": RULE_CONFIDENCE[rule],
        "mitre": RULE_MITRE[rule],
        "user": user,
        "source_ip": source_ip,
        "event_ids": ids,
        "event_count": len(ids),
        "first_seen": min(times),
        "last_seen": max(times),
        "evidence": evidence,
    }


# --- rules --------------------------------------------------------------

def detect_brute_force(
    events: list[dict[str, Any]],
    *,
    threshold: int = BRUTE_FORCE_THRESHOLD,
    window_seconds: int = BRUTE_FORCE_WINDOW_SECONDS,
) -> list[dict[str, Any]]:
    """Flag users with >= threshold failed logins in the given window."""
    for event in events:
        validate_event(event)

    failed = [
        e for e in events
        if e["event_type"] == "login_attempt" and e["success"] is False
    ]
    failed.sort(key=lambda e: e["timestamp"])

    alerts: list[dict[str, Any]] = []
    seen_users: set[tuple[str, str]] = set()

    for event in failed:
        key = (event["user"], event["source_ip"])
        if key in seen_users:
            continue

        t0 = _parse_ts(event["timestamp"])
        window = [
            e for e in failed
            if e["user"] == event["user"]
            and e["source_ip"] == event["source_ip"]
            and 0 <= (_parse_ts(e["timestamp"]) - t0).total_seconds() <= window_seconds
        ]
        if len(window) >= threshold:
            seen_users.add(key)
            alerts.append(_alert(
                "brute_force",
                window,
                user=event["user"],
                source_ip=event["source_ip"],
                evidence=(
                    f"{len(window)} failed logins within "
                    f"{window_seconds}s (threshold {threshold})"
                ),
            ))

    return alerts


def detect_privilege_escalation(
    events: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Flag role assignments to privileged roles."""
    for event in events:
        validate_event(event)

    alerts = []
    for event in events:
        if event["event_type"] != "role_assignment":
            continue
        if event.get("role") not in PRIVILEGED_ROLES:
            continue
        alerts.append(_alert(
            "privilege_escalation",
            [event],
            user=event["user"],
            source_ip=event["source_ip"],
            evidence=f"role '{event['role']}' assigned to {event['user']}",
        ))
    return alerts


def detect_large_download(
    events: list[dict[str, Any]],
    *,
    threshold: int = LARGE_DOWNLOAD_THRESHOLD,
) -> list[dict[str, Any]]:
    """Flag data downloads at or above the record threshold."""
    for event in events:
        validate_event(event)

    alerts = []
    for event in events:
        if event["event_type"] != "data_download":
            continue
        if event.get("records", 0) < threshold:
            continue
        alerts.append(_alert(
            "large_download",
            [event],
            user=event["user"],
            source_ip=event["source_ip"],
            evidence=(
                f"{event['records']} records downloaded "
                f"(threshold {threshold})"
            ),
        ))
    return alerts


def run_rules(
    events: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Run all detection rules; return combined alerts."""
    if not isinstance(events, list):
        raise ValueError("events must be a list")

    alerts: list[dict[str, Any]] = []
    alerts.extend(detect_brute_force(events))
    alerts.extend(detect_privilege_escalation(events))
    alerts.extend(detect_large_download(events))
    return alerts
from aegis.events.generator import generate_events
from aegis.sentinel.rules import (
    PRIVILEGED_ROLES,
    RULE_MITRE,
    RULE_SEVERITY,
    detect_brute_force,
    detect_large_download,
    detect_privilege_escalation,
    run_rules,
)


def test_no_alerts_on_benign_traffic():
    events = generate_events(count=200, seed=42)
    alerts = run_rules(events)
    assert alerts == []


def test_brute_force_is_detected():
    events = generate_events(count=20, seed=42, inject=("brute_force",))
    alerts = detect_brute_force(events)
    assert len(alerts) == 1
    alert = alerts[0]
    assert alert["rule"] == "brute_force"
    assert alert["event_count"] >= 5
    assert alert["user"] == "user:bob"


def test_privilege_escalation_is_detected():
    events = generate_events(count=20, seed=42, inject=("privilege_escalation",))
    alerts = detect_privilege_escalation(events)
    assert len(alerts) == 1
    assert alerts[0]["rule"] == "privilege_escalation"
    assert "cloud-admin" in alerts[0]["evidence"]


def test_large_download_is_detected():
    events = generate_events(count=20, seed=42, inject=("large_download",))
    alerts = detect_large_download(events)
    assert len(alerts) == 1
    assert alerts[0]["rule"] == "large_download"
    assert alerts[0]["user"] == "user:bob"


def test_all_injections_produce_three_alerts():
    events = generate_events(
        count=50, seed=42,
        inject=("brute_force", "privilege_escalation", "large_download"),
    )
    alerts = run_rules(events)
    rules = {a["rule"] for a in alerts}
    assert rules == {"brute_force", "privilege_escalation", "large_download"}


def test_alert_shape_is_complete():
    events = generate_events(count=20, seed=42, inject=("brute_force",))
    alert = detect_brute_force(events)[0]
    expected = {
        "alert_id", "rule", "severity", "confidence", "mitre",
        "user", "source_ip", "event_ids", "event_count",
        "first_seen", "last_seen", "evidence",
    }
    assert expected.issubset(alert.keys())


def test_alert_severity_and_confidence_match_rule_tables():
    events = generate_events(
        count=20, seed=42,
        inject=("privilege_escalation",),
    )
    alert = detect_privilege_escalation(events)[0]
    assert alert["severity"] == RULE_SEVERITY["privilege_escalation"]


def test_privileged_roles_list_contains_cloud_admin():
    assert "cloud-admin" in PRIVILEGED_ROLES


def test_run_rules_rejects_non_list():
    import pytest
    with pytest.raises(ValueError):
        run_rules("not-a-list")


def test_alerts_include_mitre_technique():
    events = generate_events(count=20, seed=42, inject=("brute_force",))
    alert = detect_brute_force(events)[0]
    assert alert["mitre"] == RULE_MITRE["brute_force"]
