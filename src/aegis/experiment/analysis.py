"""
Robustness analysis for held-out experiment results.

Answers two questions that a single run cannot:
  1. Is the improvement figure stable across random seeds? (seed sweep)
  2. Does it depend on the specific cost weights used? (weight sweep)

Both are cheap and both are necessary before the improvement number can
be presented as a finding rather than an anecdote.
"""

import statistics
from typing import Any

from aegis.experiment.runner import run_experiment


def _summarise(values: list[float]) -> dict[str, float]:
    return {
        "mean": round(statistics.mean(values), 4),
        "std": round(statistics.pstdev(values), 4),
        "min": round(min(values), 4),
        "max": round(max(values), 4),
    }


def run_seed_sweep(
    *,
    seeds: list[int],
    training_count: int = 1000,
    test_count: int = 250,
    episodes: int = 5000,
    weights: dict | None = None,
) -> dict[str, Any]:
    """
    Run the experiment once per seed and summarise the distribution of
    the improvement metric. Each seed produces a fresh training set, a
    fresh test set, and a fresh trained agent.
    """
    if not isinstance(seeds, list) or not seeds:
        raise ValueError("seeds must be a non-empty list of integers")

    per_seed = []
    for seed in seeds:
        result = run_experiment(
            training_count=training_count,
            test_count=test_count,
            episodes=episodes,
            seed=seed,
            weights=weights,
        )
        per_seed.append({
            "seed": seed,
            "improvement_pct": result["improvement_vs_best_baseline_pct"],
            "learned_mean_cost": result["evaluations"]["learned_policy"]["mean_cost"],
            "best_baseline": result["best_baseline"],
            "best_baseline_cost": result["evaluations"][result["best_baseline"]]["mean_cost"],
            "learned_policy": result["learned_policy"],
        })

    improvements = [r["improvement_pct"] for r in per_seed]

    return {
        "seeds": seeds,
        "per_seed": per_seed,
        "improvement_stats": _summarise(improvements),
        "all_runs_positive": all(v > 0 for v in improvements),
        "frac_runs_positive": sum(1 for v in improvements if v > 0) / len(improvements),
        "method": "seed_sweep",
        "limitations": [
            "All runs use the same simulator and cost model.",
            "Different seeds change scenario sampling, not the underlying "
            "distribution — this measures variance, not generalisation to "
            "new environments.",
        ],
    }


def run_weight_sweep(
    *,
    weight_grid: list[dict[str, float]],
    training_count: int = 1000,
    test_count: int = 250,
    episodes: int = 5000,
    seed: int = 42,
) -> dict[str, Any]:
    """
    Run the experiment once per cost-weight configuration, holding the
    seed fixed. Answers: does the improvement figure survive a change in
    how risk, availability, and recovery are weighted?
    """
    if not isinstance(weight_grid, list) or not weight_grid:
        raise ValueError("weight_grid must be a non-empty list of dicts")

    per_config = []
    for weights in weight_grid:
        for key in ("residual_risk", "availability_loss", "recovery_time"):
            if key not in weights:
                raise ValueError(f"weight config missing key: {key}")

        result = run_experiment(
            training_count=training_count,
            test_count=test_count,
            episodes=episodes,
            seed=seed,
            weights=weights,
        )
        per_config.append({
            "weights": dict(weights),
            "improvement_pct": result["improvement_vs_best_baseline_pct"],
            "learned_mean_cost": result["evaluations"]["learned_policy"]["mean_cost"],
            "best_baseline": result["best_baseline"],
            "learned_policy": result["learned_policy"],
        })

    improvements = [r["improvement_pct"] for r in per_config]

    return {
        "seed": seed,
        "per_config": per_config,
        "improvement_stats": _summarise(improvements),
        "all_configs_positive": all(v > 0 for v in improvements),
        "frac_configs_positive": sum(1 for v in improvements if v > 0) / len(improvements),
        "method": "weight_sweep",
        "limitations": [
            "The outcome model itself is unchanged; only scoring weights vary.",
            "A robust result across weights is necessary but not sufficient "
            "evidence that the underlying model is realistic.",
        ],
    }