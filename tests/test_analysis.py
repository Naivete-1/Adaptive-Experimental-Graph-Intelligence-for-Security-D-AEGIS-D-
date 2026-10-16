import pytest

from aegis.experiment.analysis import run_seed_sweep, run_weight_sweep


def test_seed_sweep_runs_every_seed():
    result = run_seed_sweep(
        seeds=[1, 2, 3],
        training_count=50, test_count=20, episodes=200,
    )
    assert len(result["per_seed"]) == 3
    assert [r["seed"] for r in result["per_seed"]] == [1, 2, 3]


def test_seed_sweep_reports_distribution_stats():
    result = run_seed_sweep(
        seeds=[1, 2, 3],
        training_count=50, test_count=20, episodes=200,
    )
    stats = result["improvement_stats"]
    assert set(stats.keys()) == {"mean", "std", "min", "max"}
    assert stats["min"] <= stats["mean"] <= stats["max"]


def test_seed_sweep_is_reproducible():
    a = run_seed_sweep(seeds=[1, 2], training_count=50,
                       test_count=20, episodes=200)
    b = run_seed_sweep(seeds=[1, 2], training_count=50,
                       test_count=20, episodes=200)
    assert a["improvement_stats"] == b["improvement_stats"]


def test_seed_sweep_rejects_empty_list():
    with pytest.raises(ValueError):
        run_seed_sweep(seeds=[])


def test_seed_sweep_reports_fraction_positive():
    result = run_seed_sweep(
        seeds=[1, 2, 3, 4],
        training_count=50, test_count=20, episodes=200,
    )
    assert 0.0 <= result["frac_runs_positive"] <= 1.0


def test_weight_sweep_runs_every_config():
    grid = [
        {"residual_risk": 0.6, "availability_loss": 0.3, "recovery_time": 0.1},
        {"residual_risk": 0.5, "availability_loss": 0.4, "recovery_time": 0.1},
        {"residual_risk": 0.7, "availability_loss": 0.2, "recovery_time": 0.1},
    ]
    result = run_weight_sweep(
        weight_grid=grid,
        training_count=50, test_count=20, episodes=200,
    )
    assert len(result["per_config"]) == 3
    assert [c["weights"] for c in result["per_config"]] == grid


def test_weight_sweep_reports_distribution():
    grid = [
        {"residual_risk": 0.6, "availability_loss": 0.3, "recovery_time": 0.1},
        {"residual_risk": 0.5, "availability_loss": 0.4, "recovery_time": 0.1},
    ]
    result = run_weight_sweep(
        weight_grid=grid,
        training_count=50, test_count=20, episodes=200,
    )
    assert set(result["improvement_stats"].keys()) == {"mean", "std", "min", "max"}


def test_weight_sweep_rejects_empty_grid():
    with pytest.raises(ValueError):
        run_weight_sweep(weight_grid=[])


def test_weight_sweep_rejects_incomplete_config():
    with pytest.raises(ValueError):
        run_weight_sweep(
            weight_grid=[{"residual_risk": 0.5}],
            training_count=50, test_count=20, episodes=200,
        )


def test_weight_sweep_is_reproducible():
    grid = [
        {"residual_risk": 0.6, "availability_loss": 0.3, "recovery_time": 0.1},
        {"residual_risk": 0.4, "availability_loss": 0.5, "recovery_time": 0.1},
    ]
    a = run_weight_sweep(weight_grid=grid, training_count=50,
                         test_count=20, episodes=200, seed=42)
    b = run_weight_sweep(weight_grid=grid, training_count=50,
                         test_count=20, episodes=200, seed=42)
    assert a["improvement_stats"] == b["improvement_stats"]