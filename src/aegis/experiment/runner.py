"""
Held-out experiment runner.

This is the piece the docs said was missing: scenario generation, policy
training, and evaluation are wired into one pipeline, and the learned
policy is compared against fixed baselines on scenarios the agent has
never seen.

Method:
  1. Generate training scenarios (seed A) and test scenarios (seed B).
  2. Train the Q-learner on the training set.
  3. Evaluate the learned policy and three fixed baselines on the SAME
     held-out test set.
  4. Report per-policy aggregates plus improvement over the best baseline.

The improvement number is only meaningful under the simulated outcome
model and its documented assumptions. It is not a real-world result.
"""

from typing import Any

from aegis.agents.learner import (
    evaluate_policy,
    fixed_policy,
    train_agent,
)
from aegis.scenarios.generator import generate_scenarios


BASELINE_ACTIONS = {
    "always_revoke_privilege": "revoke_privilege",
    "always_disable_identity": "disable_identity",
    "always_isolate_service": "isolate_service",
}


def run_experiment(
    *,
    training_count: int = 1000,
    test_count: int = 250,
    episodes: int = 5000,
    seed: int = 42,
    weights: dict | None = None,
) -> dict[str, Any]:
    """
    Run the full held-out experiment.

    Training and test scenarios use disjoint seeds and therefore disjoint
    scenario IDs. Both the learned policy and each fixed baseline are
    evaluated on the same test set.
    """
    # --- 1. Generate disjoint scenario sets ---------------------------
    training_scenarios = generate_scenarios(count=training_count, seed=seed)
    test_scenarios = generate_scenarios(count=test_count, seed=seed + 1)

    train_ids = {s["scenario_id"] for s in training_scenarios}
    test_ids = {s["scenario_id"] for s in test_scenarios}
    if train_ids & test_ids:
        raise RuntimeError("Training and test scenario IDs overlap")

    # --- 2. Train -----------------------------------------------------
    learned = train_agent(
        training_scenarios=training_scenarios,
        episodes=episodes,
        seed=seed,
        weights=weights,
    )
    # --- 3. Evaluate on held-out test set -----------------------------
    evaluations: dict[str, dict[str, Any]] = {}

    evaluations["learned_policy"] = evaluate_policy(
        learned, test_scenarios, weights=weights
    )

    for name, action in BASELINE_ACTIONS.items():
        baseline = fixed_policy(action)
        evaluations[name] = evaluate_policy(
            baseline, test_scenarios, weights=weights
        )

    # --- 4. Compute improvement vs best baseline ----------------------
    baseline_costs = {
        name: report["mean_cost"]
        for name, report in evaluations.items()
        if name != "learned_policy"
    }
    best_baseline_name = min(baseline_costs, key=baseline_costs.get)
    best_baseline_cost = baseline_costs[best_baseline_name]
    learned_cost = evaluations["learned_policy"]["mean_cost"]

    if best_baseline_cost > 0:
        improvement_pct = (
            (best_baseline_cost - learned_cost) / best_baseline_cost * 100
        )
    else:
        improvement_pct = 0.0

    # --- 5. Assemble report -------------------------------------------
    summary_rows = []
    for name, report in evaluations.items():
        summary_rows.append({
            "policy": name,
            "mean_cost": report["mean_cost"],
            "mean_residual_risk": report["mean_residual_risk"],
            "mean_service_availability": report["mean_service_availability"],
            "mean_recovery_minutes": report["mean_recovery_minutes"],
            "scenarios_evaluated": report["scenarios_evaluated"],
        })
    summary_rows.sort(key=lambda r: r["mean_cost"])

    return {
        "config": {
            "training_count": training_count,
            "test_count": test_count,
            "episodes": episodes,
            "seed": seed,
        },
        "learned_policy": learned["policy"],
        "learned_q_values": learned["q_values"],
        "evaluations": evaluations,
        "summary": summary_rows,
        "improvement_vs_best_baseline_pct": round(improvement_pct, 4),
        "best_baseline": best_baseline_name,
        "method": "held_out_experiment",
        "limitations": [
            "Outcomes come from a documented, assumption-based simulator.",
            "The agent's state is (severity, criticality) only; attack type, "
            "detection confidence, and compromise scope affect outcomes but "
            "are not visible to the agent.",
            "The decision is one-step; there are no sequential transitions.",
            "Improvement figures depend on the simulated cost model and its "
            "provisional weights.",
            "This does not establish real-world response effectiveness.",
        ],
    }