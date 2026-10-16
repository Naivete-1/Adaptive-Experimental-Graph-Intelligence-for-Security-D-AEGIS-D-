import pytest

from aegis.experiment.runner import BASELINE_ACTIONS, run_experiment


def test_run_experiment_returns_expected_structure():
    result = run_experiment(
        training_count=200, test_count=50, episodes=500, seed=42
    )
    assert "config" in result
    assert "learned_policy" in result
    assert "evaluations" in result
    assert "summary" in result
    assert "improvement_vs_best_baseline_pct" in result
    assert "limitations" in result


def test_run_experiment_honours_config():
    result = run_experiment(
        training_count=100, test_count=30, episodes=200, seed=7
    )
    assert result["config"]["training_count"] == 100
    assert result["config"]["test_count"] == 30
    assert result["config"]["episodes"] == 200
    assert result["config"]["seed"] == 7


def test_all_policies_evaluated_on_same_test_count():
    result = run_experiment(
        training_count=100, test_count=40, episodes=200, seed=1
    )
    for name, report in result["evaluations"].items():
        assert report["scenarios_evaluated"] == 40, name


def test_summary_includes_learned_and_all_baselines():
    result = run_experiment(
        training_count=100, test_count=20, episodes=200, seed=1
    )
    policy_names = {row["policy"] for row in result["summary"]}
    assert "learned_policy" in policy_names
    for name in BASELINE_ACTIONS:
        assert name in policy_names


def test_summary_is_sorted_by_mean_cost():
    result = run_experiment(
        training_count=200, test_count=50, episodes=500, seed=1
    )
    costs = [row["mean_cost"] for row in result["summary"]]
    assert costs == sorted(costs)


def test_experiment_is_reproducible():
    a = run_experiment(training_count=100, test_count=20, episodes=200, seed=3)
    b = run_experiment(training_count=100, test_count=20, episodes=200, seed=3)
    assert a["learned_policy"] == b["learned_policy"]
    assert a["improvement_vs_best_baseline_pct"] == b["improvement_vs_best_baseline_pct"]
    assert a["summary"] == b["summary"]


def test_learned_policy_beats_best_baseline_on_held_out_set():
    """
    The research claim. Under the current simulated model, with the current
    modulation factors and cost weights, the learned policy should not be
    worse than the best fixed baseline on the held-out test set.
    """
    result = run_experiment(
        training_count=2000, test_count=500, episodes=20000, seed=42
    )
    assert result["improvement_vs_best_baseline_pct"] >= -1e-6