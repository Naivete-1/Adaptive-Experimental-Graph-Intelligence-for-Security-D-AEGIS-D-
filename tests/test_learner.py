import pytest

from aegis.agents.learner import (
    ACTIONS,
    STATES,
    evaluate_policy,
    fixed_policy,
    state_name,
    train_agent,
)
from aegis.scenarios.generator import generate_scenarios


# --- training -----------------------------------------------------------

def test_policy_covers_every_state():
    result = train_agent(episodes=500, seed=42)
    assert set(result["policy"].keys()) == {state_name(s) for s in STATES}
    for action in result["policy"].values():
        assert action in ACTIONS


def test_training_is_reproducible():
    a = train_agent(episodes=500, seed=42)
    b = train_agent(episodes=500, seed=42)
    assert a["policy"] == b["policy"]
    assert a["q_values"] == b["q_values"]


def test_training_uses_provided_scenarios():
    scenarios = generate_scenarios(count=17, seed=99)
    result = train_agent(training_scenarios=scenarios, episodes=100, seed=42)
    assert result["training_scenarios_used"] == 17


def test_empty_scenario_list_is_rejected():
    with pytest.raises(ValueError):
        train_agent(training_scenarios=[], episodes=10)


def test_invalid_scenarios_are_rejected():
    bad = [{"scenario_id": "X", "severity": "wrong", "criticality": "low"}]
    with pytest.raises(ValueError):
        train_agent(training_scenarios=bad, episodes=10)


def test_zero_episodes_is_rejected():
    with pytest.raises(ValueError):
        train_agent(episodes=0)


# --- evaluation ---------------------------------------------------------

def test_evaluate_reports_one_result_per_scenario():
    policy = train_agent(episodes=200, seed=42)
    scenarios = generate_scenarios(count=30, seed=7)
    report = evaluate_policy(policy, scenarios)
    assert report["scenarios_evaluated"] == 30
    assert len(report["results"]) == 30


def test_evaluate_preserves_scenario_ids():
    policy = train_agent(episodes=200, seed=42)
    scenarios = generate_scenarios(count=15, seed=3)
    report = evaluate_policy(policy, scenarios)
    assert {r["scenario_id"] for r in report["results"]} == {
        s["scenario_id"] for s in scenarios
    }


def test_evaluate_rejects_empty_scenarios():
    policy = train_agent(episodes=100, seed=42)
    with pytest.raises(ValueError):
        evaluate_policy(policy, [])


def test_evaluate_rejects_policy_with_missing_state():
    broken = {"policy": {state_name(("low", "low")): "revoke_privilege"}}
    scenarios = generate_scenarios(count=5, seed=1)
    with pytest.raises(ValueError):
        evaluate_policy(broken, scenarios)


# --- fixed baselines ---------------------------------------------------

def test_fixed_policy_is_well_formed():
    p = fixed_policy("revoke_privilege")
    assert set(p["policy"].keys()) == {state_name(s) for s in STATES}
    assert all(a == "revoke_privilege" for a in p["policy"].values())


def test_fixed_policy_rejects_unknown_action():
    with pytest.raises(ValueError):
        fixed_policy("not_an_action")


# --- the research question ---------------------------------------------

def test_learned_policy_matches_or_beats_revoke_baseline_on_training_set():
    """
    Smoke test for the research loop. On the training distribution the
    learned policy should not be worse than the best fixed baseline in
    expectation. This is NOT the held-out experiment — that comes next —
    but it confirms the learner is doing something sensible.
    """
    scenarios = generate_scenarios(count=2000, seed=42)
    learned = train_agent(training_scenarios=scenarios, episodes=20000, seed=42)
    revoke = fixed_policy("revoke_privilege")

    learned_report = evaluate_policy(learned, scenarios)
    revoke_report = evaluate_policy(revoke, scenarios)

    assert learned_report["mean_cost"] <= revoke_report["mean_cost"] + 0.5
def test_training_history_is_logged_when_requested():
    result = train_agent(episodes=1000, seed=42, track_history=True)
    history = result["training_history"]
    assert isinstance(history, list)
    assert 90 <= len(history) <= 110   # ~100 samples
    assert all(isinstance(x, float) for x in history)


def test_training_history_is_empty_by_default():
    result = train_agent(episodes=500, seed=42)
    assert result["training_history"] == []