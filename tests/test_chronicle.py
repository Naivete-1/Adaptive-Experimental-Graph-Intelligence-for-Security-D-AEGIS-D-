import pytest

from aegis.chronicle.correlator import correlate_alerts
from aegis.events.generator import generate_events
from aegis.sentinel.rules import run_rules


def _scenario_with_all_injections(count: int = 50, seed: int = 42):
    events = generate_events(
        count=count, seed=seed,
        inject=("brute_force", "privilege_escalation", "large_download"),
    )
    alerts = run_rules(events)
    return events, alerts


# --- basics ------------------------------------------------------------

def test_empty_alerts_produces_no_incidents():
    assert correlate_alerts([]) == []


def test_rejects_non_list_alerts():
    with pytest.raises(ValueError):
        correlate_alerts("not-a-list")


def test_rejects_negative_window():
    with pytest.raises(ValueError):
        correlate_alerts([], window_seconds=-1)


# --- single alert ------------------------------------------------------

def test_single_alert_produces_one_incident():
    events = generate_events(count=20, seed=42, inject=("large_download",))
    alerts = run_rules(events)
    incidents = correlate_alerts(alerts, events)

    assert len(incidents) == 1
    incident = incidents[0]
    assert incident["user"] == "user:bob"
    assert incident["alert_count"] == 1
    assert incident["rule_names"] == ["large_download"]
    assert incident["status"] == "open"


# --- multiple alerts on same user --------------------------------------

def test_all_injections_on_same_user_cluster_into_one_incident():
    """
    All three injections target user:bob. Within the default 15-minute
    window, they should cluster into a single incident.
    """
    events, alerts = _scenario_with_all_injections()
    incidents = correlate_alerts(alerts, events)

    bob_incidents = [i for i in incidents if i["user"] == "user:bob"]
    assert len(bob_incidents) == 1
    incident = bob_incidents[0]
    assert incident["alert_count"] == 3
    assert set(incident["rule_names"]) == {
        "brute_force", "privilege_escalation", "large_download",
    }
    assert incident["severity"] == "high"  # max of the three rules


def test_incident_carries_events_from_all_alerts():
    events, alerts = _scenario_with_all_injections()
    incidents = correlate_alerts(alerts, events)
    bob_incident = [i for i in incidents if i["user"] == "user:bob"][0]

    # Every event the alerts referenced is present in incident["events"].
    referenced = set(bob_incident["event_ids"])
    present = {e["event_id"] for e in bob_incident["events"]}
    assert referenced == present
    assert len(present) >= 7  # 5 brute-force + 1 priv-esc + 1 download


# --- window behaviour --------------------------------------------------

def test_small_window_splits_incidents():
    """
    With a very small window, the three injections on bob should no
    longer cluster together (they occur at different times).
    """
    events, alerts = _scenario_with_all_injections()
    incidents = correlate_alerts(alerts, events, window_seconds=1)

    bob_incidents = [i for i in incidents if i["user"] == "user:bob"]
    assert len(bob_incidents) > 1


# --- multiple users ----------------------------------------------------

def test_alerts_on_different_users_produce_separate_incidents():
    """
    Build a synthetic set of alerts for two different users and confirm
    they do not merge.
    """
    alerts = [
        {
            "alert_id": "A1", "rule": "large_download", "severity": "high",
            "confidence": 0.9, "user": "user:alice", "source_ip": "ip1",
            "event_ids": ["E1"], "event_count": 1,
            "first_seen": "2026-01-01T12:00:00Z",
            "last_seen": "2026-01-01T12:00:00Z",
            "evidence": "x",
        },
        {
            "alert_id": "A2", "rule": "large_download", "severity": "high",
            "confidence": 0.9, "user": "user:carol", "source_ip": "ip2",
            "event_ids": ["E2"], "event_count": 1,
            "first_seen": "2026-01-01T12:00:30Z",
            "last_seen": "2026-01-01T12:00:30Z",
            "evidence": "x",
        },
    ]
    incidents = correlate_alerts(alerts)
    assert len(incidents) == 2
    users = {i["user"] for i in incidents}
    assert users == {"user:alice", "user:carol"}


# --- shape -------------------------------------------------------------

def test_incident_has_expected_fields():
    events, alerts = _scenario_with_all_injections()
    incidents = correlate_alerts(alerts, events)
    expected = {
        "incident_id", "user", "status", "first_seen", "last_seen",
        "alert_ids", "alert_count", "rule_names", "severity",
        "confidence", "event_ids", "event_count", "events", "summary",
        "correlation_note",
    }
    for incident in incidents:
        assert expected.issubset(incident.keys())


def test_incidents_are_sorted_by_first_seen():
    events, alerts = _scenario_with_all_injections()
    incidents = correlate_alerts(alerts, events)
    timestamps = [i["first_seen"] for i in incidents]
    assert timestamps == sorted(timestamps)


def test_incident_correlation_note_is_honest():
    events, alerts = _scenario_with_all_injections()
    incidents = correlate_alerts(alerts, events)
    for incident in incidents:
        assert "not establish" in incident["correlation_note"].lower()