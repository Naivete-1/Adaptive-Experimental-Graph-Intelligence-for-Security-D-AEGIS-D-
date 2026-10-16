import pytest

from aegis.chronicle.bridge import (
    DEFAULT_CRITICALITY,
    incident_to_scenario,
    incidents_to_scenarios,
)
from aegis.chronicle.correlator import correlate_alerts
from aegis.events.generator import generate_events
from aegis.sentinel.rules import run_rules
from aegis.simulator.response_lab import ACTIONS, simulate_response


def _sample_incident(**overrides):
    base = {
        "incident_id": "INC-00001",
        "user": "user:bob",
        "status": "open",
        "first_seen": "2026-01-01T12:00:00Z",
        "last_seen": "2026-01-01T12:10:00Z",
        "alert_ids": ["A1"],
        "alert_count": 1,
        "rule_names": ["brute_force"],
        "severity": "medium",
        "confidence": 0.7,
        "event_ids": ["E1"],
        "event_count": 1,
        "events": [{"event_id": "E1", "resource": "report:weekly"}],
        "summary": "x",
        "correlation_note": "y",
    }
    base.update(overrides)
    return base


# --- basic shape ---------------------------------------------------------

def test_converts_one_incident_to_one_scenario():
    scenario = incident_to_scenario(_sample_incident())
    assert scenario["scenario_id"] == "SCN-FROM-INC-00001"
    assert scenario["source_incident_id"] == "INC-00001"


def test_scenario_has_all_required_fields():
    scenario = incident_to_scenario(_sample_incident())
    expected = {
        "scenario_id", "severity", "criticality", "attack_type",
        "detection_confidence", "compromise_scope",
        "initial_risk", "initial_availability",
        "source_incident_id", "environment",
    }
    assert expected.issubset(scenario.keys())


def test_empty_incident_list_produces_empty_scenario_list():
    assert incidents_to_scenarios([]) == []


def test_rejects_non_dict_incident():
    with pytest.raises(ValueError):
        incident_to_scenario("not-a-dict")


def test_rejects_incident_missing_fields():
    with pytest.raises(ValueError):
        incident_to_scenario({"incident_id": "INC-1"})


def test_rejects_invalid_severity():
    with pytest.raises(ValueError):
        incident_to_scenario(_sample_incident(severity="catastrophic"))


# --- feature derivation --------------------------------------------------

def test_severity_is_preserved():
    for severity, expected_risk in (("low", 30), ("medium", 60), ("high", 90)):
        scenario = incident_to_scenario(_sample_incident(severity=severity))
        assert scenario["severity"] == severity
        assert scenario["initial_risk"] == expected_risk


def test_attack_type_maps_from_highest_priority_rule():
    # privilege_escalation outranks brute_force.
    scenario = incident_to_scenario(
        _sample_incident(rule_names=["brute_force", "privilege_escalation"])
    )
    assert scenario["attack_type"] == "privilege_escalation"


def test_large_download_maps_to_data_exfiltration():
    scenario = incident_to_scenario(
        _sample_incident(rule_names=["large_download"])
    )
    assert scenario["attack_type"] == "data_exfiltration"


def test_detection_confidence_is_binned():
    cases = [
        (0.30, "low"),
        (0.49, "low"),
        (0.50, "medium"),
        (0.79, "medium"),
        (0.80, "high"),
        (1.00, "high"),
    ]
    for numeric, expected in cases:
        scenario = incident_to_scenario(
            _sample_incident(confidence=numeric)
        )
        assert scenario["detection_confidence"] == expected, numeric


def test_scope_derived_from_rule_count():
    one = incident_to_scenario(
        _sample_incident(rule_names=["brute_force"])
    )
    two = incident_to_scenario(
        _sample_incident(rule_names=["brute_force", "privilege_escalation"])
    )
    three = incident_to_scenario(
        _sample_incident(
            rule_names=["brute_force", "privilege_escalation", "large_download"]
        )
    )
    assert one["compromise_scope"] == "single_identity"
    assert two["compromise_scope"] == "multiple_identities"
    assert three["compromise_scope"] == "service_affected"


def test_criticality_derived_from_sensitive_resource():
    sensitive = incident_to_scenario(_sample_incident(
        events=[{"event_id": "E1", "resource": "dataset:customer-pii"}],
    ))
    benign = incident_to_scenario(_sample_incident(
        events=[{"event_id": "E1", "resource": "report:weekly"}],
    ))
    unknown = incident_to_scenario(_sample_incident(
        events=[{"event_id": "E1", "resource": "not:in:map"}],
    ))
    assert sensitive["criticality"] == "high"
    assert benign["criticality"] == "low"
    assert unknown["criticality"] == DEFAULT_CRITICALITY


def test_criticality_takes_highest_sensitivity_in_incident():
    scenario = incident_to_scenario(_sample_incident(
        events=[
            {"event_id": "E1", "resource": "report:weekly"},
            {"event_id": "E2", "resource": "dataset:customer-pii"},
        ],
    ))
    assert scenario["criticality"] == "high"


# --- compatibility with the simulator -----------------------------------

def test_bridged_scenario_is_valid_for_simulator():
    """
    The scenario produced by the bridge must be accepted by the simulator
    without modification. This is the contract that makes the two worlds
    compatible.
    """
    scenario = incident_to_scenario(_sample_incident(
        rule_names=["brute_force", "privilege_escalation", "large_download"],
        events=[
            {"event_id": "E1", "resource": "dataset:customer-pii"},
        ],
        confidence=0.9,
        severity="high",
    ))
    for action in ACTIONS:
        outcome = simulate_response(action, scenario)
        assert outcome["scenario_id"] == scenario["scenario_id"]


# --- end-to-end from events ---------------------------------------------

def test_bridge_from_real_detected_incident():
    """
    Full pipeline: generate events with all three injections, run rules,
    correlate into incidents, convert to scenarios, and confirm each
    scenario is simulatable and derives expected features.
    """
    events = generate_events(
        count=50, seed=42,
        inject=("brute_force", "privilege_escalation", "large_download"),
    )
    alerts = run_rules(events)
    incidents = correlate_alerts(alerts, events)

    bob_incidents = [i for i in incidents if i["user"] == "user:bob"]
    assert len(bob_incidents) == 1

    scenario = incident_to_scenario(bob_incidents[0])

    # Attack chain begins with brute force, escalates, then exfiltrates.
    # The highest-priority rule is privilege_escalation.
    assert scenario["attack_type"] == "privilege_escalation"
    assert scenario["compromise_scope"] == "service_affected"
    assert scenario["criticality"] == "high"   # customer-pii download
    assert scenario["detection_confidence"] == "high"  # 0.9 confidence
    assert scenario["severity"] == "high"      # max rule severity

    # And it is a valid simulator input.
    for action in ACTIONS:
        simulate_response(action, scenario)
def test_criticality_defaults_only_when_no_known_resource():
    """
    If no event references a known resource, criticality is the default.
    If a known low-sensitivity resource is referenced, criticality is
    low — the default is not a floor.
    """
    no_resource = incident_to_scenario(_sample_incident(
        events=[{"event_id": "E1"}],
    ))
    unknown_resource = incident_to_scenario(_sample_incident(
        events=[{"event_id": "E1", "resource": "not:in:map"}],
    ))
    low_resource = incident_to_scenario(_sample_incident(
        events=[{"event_id": "E1", "resource": "report:weekly"}],
    ))

    assert no_resource["criticality"] == DEFAULT_CRITICALITY
    assert unknown_resource["criticality"] == DEFAULT_CRITICALITY
    assert low_resource["criticality"] == "low"
from aegis.attackgraph.graph import build_default_graph


def test_criticality_uses_graph_when_provided():
    """
    Bob can reach resource:customer-db in the default graph. An incident
    on bob with no sensitive resource in its events should still be
    classified high because of what bob *could* reach.
    """
    g = build_default_graph()
    incident = _sample_incident(
        user="user:bob",
        events=[{"event_id": "E1", "resource": "report:weekly"}],
    )
    scenario = incident_to_scenario(incident, graph=g)
    assert scenario["criticality"] == "high"


def test_graph_reachability_overrides_low_resource():
    """
    Even if the incident only touches a low-sensitivity resource, an
    identity that can reach a high-sensitivity resource is critical.
    """
    g = build_default_graph()
    incident = _sample_incident(
        user="user:bob",
        events=[{"event_id": "E1", "resource": "report:weekly"}],
    )
    with_graph = incident_to_scenario(incident, graph=g)
    without_graph = incident_to_scenario(incident)
    assert without_graph["criticality"] == "low"
    assert with_graph["criticality"] == "high"


def test_alice_is_only_medium_criticality():
    """
    Alice reaches the public dashboard (low sensitivity). Direct length-1
    paths get bumped by classify_path_risk, but for criticality we use
    the resource's declared sensitivity, not path risk. So alice is low.
    """
    g = build_default_graph()
    incident = _sample_incident(
        user="user:alice",
        events=[{"event_id": "E1", "resource": "report:weekly"}],
    )
    scenario = incident_to_scenario(incident, graph=g)
    assert scenario["criticality"] == "low"


def test_unknown_user_falls_back_to_resource_lookup():
    """
    A user not in the graph should fall back to the name-based resource
    lookup, not raise.
    """
    g = build_default_graph()
    incident = _sample_incident(
        user="user:nobody",
        events=[{"event_id": "E1", "resource": "dataset:customer-pii"}],
    )
    scenario = incident_to_scenario(incident, graph=g)
    assert scenario["criticality"] == "high"


def test_incidents_to_scenarios_threads_graph():
    g = build_default_graph()
    incidents = [
        _sample_incident(
            incident_id="INC-1", user="user:bob",
            events=[{"event_id": "E1", "resource": "report:weekly"}],
        ),
        _sample_incident(
            incident_id="INC-2", user="user:alice",
            events=[{"event_id": "E2", "resource": "report:weekly"}],
        ),
    ]
    scenarios = incidents_to_scenarios(incidents, graph=g)
    by_id = {s["source_incident_id"]: s for s in scenarios}
    assert by_id["INC-1"]["criticality"] == "high"
    assert by_id["INC-2"]["criticality"] == "low"