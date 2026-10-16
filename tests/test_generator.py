import pytest

from aegis.scenarios.generator import generate_scenarios


def test_generates_requested_count():
    scenarios = generate_scenarios(count=10, seed=42)
    assert len(scenarios) == 10


def test_generation_is_reproducible():
    first = generate_scenarios(count=10, seed=42)
    second = generate_scenarios(count=10, seed=42)
    assert first == second


def test_scenario_ids_are_unique():
    scenarios = generate_scenarios(count=100, seed=42)
    ids = [s["scenario_id"] for s in scenarios]
    assert len(ids) == len(set(ids))


def test_scenario_has_expected_fields():
    scenario = generate_scenarios(count=1, seed=42)[0]

    expected = {
        "scenario_id",
        "severity",
        "criticality",
        "attack_type",
        "detection_confidence",
        "compromise_scope",
        "initial_risk",
        "initial_availability",
        "seed",
        "environment",
    }
    assert expected.issubset(scenario.keys())


def test_initial_risk_matches_severity():
    scenarios = generate_scenarios(count=200, seed=42)
    for s in scenarios:
        expected_risk = {"low": 30, "medium": 60, "high": 90}[s["severity"]]
        assert s["initial_risk"] == expected_risk


def test_zero_count_is_rejected():
    with pytest.raises(ValueError):
        generate_scenarios(count=0)


def test_negative_count_is_rejected():
    with pytest.raises(ValueError):
        generate_scenarios(count=-5)


def test_non_integer_seed_is_rejected():
    with pytest.raises(ValueError):
        generate_scenarios(count=5, seed="not-a-seed")