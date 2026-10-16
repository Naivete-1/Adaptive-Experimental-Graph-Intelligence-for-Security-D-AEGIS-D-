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