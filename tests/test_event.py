import pytest

from aegis.events.generator import generate_events
from aegis.events.schema import EVENT_TYPES, validate_event


def test_generates_requested_count():
    events = generate_events(count=50, seed=42)
    assert len(events) == 50


def test_generation_is_reproducible():
    a = generate_events(count=30, seed=1)
    b = generate_events(count=30, seed=1)
    assert a == b


def test_event_ids_are_unique():
    events = generate_events(count=100, seed=42)
    ids = [e["event_id"] for e in events]
    assert len(ids) == len(set(ids))


def test_events_have_valid_types():
    events = generate_events(count=100, seed=42)
    for event in events:
        assert event["event_type"] in EVENT_TYPES


def test_events_pass_validation():
    events = generate_events(count=50, seed=42)
    for event in events:
        validate_event(event)


def test_injection_brute_force_adds_failed_logins():
    events = generate_events(count=10, seed=42, inject=("brute_force",))
    failures = [
        e for e in events
        if e["event_type"] == "login_attempt" and e["success"] is False
        and e["source_ip"] == "203.0.113.99"
    ]
    assert len(failures) >= 5


def test_injection_privilege_escalation_adds_cloud_admin():
    events = generate_events(count=10, seed=42, inject=("privilege_escalation",))
    priv = [
        e for e in events
        if e["event_type"] == "role_assignment" and e["role"] == "cloud-admin"
    ]
    assert len(priv) >= 1


def test_injection_large_download_adds_20000_record_event():
    events = generate_events(count=10, seed=42, inject=("large_download",))
    big = [e for e in events if e.get("records", 0) >= 20000]
    assert len(big) == 1


def test_unknown_injection_is_rejected():
    with pytest.raises(ValueError):
        generate_events(count=5, seed=1, inject=("not_a_real_pattern",))


def test_zero_count_is_rejected():
    with pytest.raises(ValueError):
        generate_events(count=0)


def test_validation_rejects_missing_fields():
    with pytest.raises(ValueError):
        validate_event({"event_id": "X"})


def test_validation_rejects_bad_event_type():
    with pytest.raises(ValueError):
        validate_event({
            "event_id": "X", "timestamp": "2026-01-01T00:00:00Z",
            "event_type": "made_up", "user": "u", "source_ip": "ip",
        })


def test_validation_requires_success_for_login_attempts():
    with pytest.raises(ValueError):
        validate_event({
            "event_id": "X", "timestamp": "2026-01-01T00:00:00Z",
            "event_type": "login_attempt", "user": "u", "source_ip": "ip",
        })


def test_benign_events_never_assign_privileged_roles():
    """
    In this synthetic world benign traffic must not assign cloud-admin
    (or any privileged role). The privilege_escalation rule relies on
    this so that it fires only on the injection.
    """
    from aegis.sentinel.rules import PRIVILEGED_ROLES

    events = generate_events(count=500, seed=42)
    for event in events:
        if event["event_type"] == "role_assignment":
            assert event["role"] not in PRIVILEGED_ROLES


def test_injected_attack_chain_clusters_within_default_window():
    """
    The three injected patterns should occur close enough in time that
    Chronicle's default 15-minute window groups them into one incident.
    """
    from aegis.chronicle.correlator import (
        DEFAULT_WINDOW_SECONDS,
        correlate_alerts,
    )
    from aegis.sentinel.rules import run_rules

    events = generate_events(
        count=50, seed=42,
        inject=("brute_force", "privilege_escalation", "large_download"),
    )
    alerts = run_rules(events)
    incidents = correlate_alerts(alerts, events)

    bob_incidents = [i for i in incidents if i["user"] == "user:bob"]
    assert len(bob_incidents) == 1, (
        f"Expected one incident for user:bob within the "
        f"{DEFAULT_WINDOW_SECONDS}s window, got {len(bob_incidents)}"
    )