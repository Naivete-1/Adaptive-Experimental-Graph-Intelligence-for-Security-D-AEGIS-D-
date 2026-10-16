"""
Adaptive Decision Engine — tabular Q-learner.

The agent sees a scenario's (severity, criticality) as its state, picks a
response action, and learns from the simulated cost of that action.

Important limitations of this version:
  * One-step decision — discount factor is fixed at 0.0.
  * The state only carries (severity, criticality). Attack type, detection
    confidence, and compromise scope affect the *outcome* but are not
    visible to the agent. This is deliberate for v0.2: it makes the
    limitation explicit rather than hiding it in a larger state space.
  * Training and evaluation both run against the same simulated model.
"""

import random
from typing import Any

from aegis.scenarios.generator import generate_scenarios
from aegis.simulator.response_lab import (
    ACTIONS,
    calculate_response_cost,
    simulate_response,
)


SEVERITIES = ("low", "medium", "high")
CRITICALITIES = ("low", "medium", "high")

STATES: list[tuple[str, str]] = [
    (s, c) for s in SEVERITIES for c in CRITICALITIES
]


def state_name(state: tuple[str, str]) -> str:
    """Stable string key for a (severity, criticality) state."""
    severity, criticality = state
    return f"{severity}_severity_{criticality}_criticality"


def _scenario_state(scenario: dict) -> tuple[str, str]:
    severity = scenario.get("severity")
    criticality = scenario.get("criticality")
    if severity not in SEVERITIES:
        raise ValueError(f"scenario has invalid severity: {severity!r}")
    if criticality not in CRITICALITIES:
        raise ValueError(f"scenario has invalid criticality: {criticality!r}")
    return (severity, criticality)


def _greedy_action(q_values: dict[str, float], rng: random.Random) -> str:
    best = max(q_values.values())
    best_actions = [a for a, v in q_values.items() if v == best]
    return rng.choice(best_actions)


def _action_cost(
    scenario: dict,
    action: str,
    weights: dict | None = None,
) -> float:
    outcome = simulate_response(action, scenario)
    return calculate_response_cost(outcome, weights)


def train_agent(
    *,
    training_scenarios: list[dict] | None = None,
    episodes: int = 5000,
    learning_rate: float = 0.1,
    epsilon: float = 0.2,
    seed: int = 42,
    weights: dict | None = None,
    track_history: bool = False,
) -> dict[str, Any]:
    """
    Learn a response policy from scenarios.

    If training_scenarios is None, generate_scenarios() is called with the
    given seed. The discount factor is fixed at 0.0 — this is a one-step
    decision problem, not a sequential RL environment.

    When track_history is True, a rolling-mean cost curve is recorded in
    the returned dict under "training_history".
    """
    if isinstance(episodes, bool) or not isinstance(episodes, int) or episodes < 1:
        raise ValueError("episodes must be a positive integer")
    if not 0 < learning_rate <= 1:
        raise ValueError("learning_rate must be between 0 and 1")
    if not 0 <= epsilon <= 1:
        raise ValueError("epsilon must be between 0 and 1")
    if isinstance(seed, bool) or not isinstance(seed, int):
        raise ValueError("seed must be an integer")

    if training_scenarios is None:
        training_scenarios = generate_scenarios(count=1000, seed=seed)
    if not isinstance(training_scenarios, list) or not training_scenarios:
        raise ValueError("training_scenarios must be a non-empty list")

    rng = random.Random(seed)

    q_table: dict[tuple[str, str], dict[str, float]] = {
        state: {action: 0.0 for action in ACTIONS} for state in STATES
    }

    history_window: list[float] = []
    history: list[float] = []
    log_every = max(1, episodes // 100)

    for _ in range(episodes):
        scenario = rng.choice(training_scenarios)
        state = _scenario_state(scenario)

        if rng.random() < epsilon:
            action = rng.choice(ACTIONS)
        else:
            action = _greedy_action(q_table[state], rng)

        reward = -_action_cost(scenario, action, weights)
        old_value = q_table[state][action]
        # discount_factor is 0, so no next_value term.
        q_table[state][action] = old_value + learning_rate * (reward - old_value)

        if track_history:
            history_window.append(-reward)
            if len(history_window) == log_every:
                history.append(
                    round(sum(history_window) / len(history_window), 4)
                )
                history_window = []

    policy = {
        state_name(state): _greedy_action(q_table[state], rng)
        for state in STATES
    }

    return {
        "algorithm": "tabular_q_learning_one_step",
        "episodes": episodes,
        "seed": seed,
        "learning_rate": learning_rate,
        "epsilon": epsilon,
        "discount_factor": 0.0,
        "training_scenarios_used": len(training_scenarios),
        "state_count": len(STATES),
        "action_count": len(ACTIONS),
        "policy": policy,
        "q_values": {
            state_name(state): dict(values) for state, values in q_table.items()
        },
        "training_history": history,
    }


def evaluate_policy(
    policy: dict[str, Any],
    scenarios: list[dict],
    weights: dict | None = None,
) -> dict[str, Any]:
    """
    Apply a policy to a set of scenarios and report per-scenario and
    aggregate outcomes. The policy is a dict mapping state_name -> action,
    so this can evaluate learned and fixed policies identically.
    """
    if not isinstance(policy, dict) or "policy" not in policy:
        raise ValueError("policy must be a dict containing a 'policy' key")
    mapping = policy["policy"]
    if not isinstance(mapping, dict):
        raise ValueError("policy['policy'] must be a dict")

    if not isinstance(scenarios, list) or not scenarios:
        raise ValueError("scenarios must be a non-empty list")

    results: list[dict[str, Any]] = []

    for scenario in scenarios:
        state = _scenario_state(scenario)
        name = state_name(state)
        action = mapping.get(name)
        if action not in ACTIONS:
            raise ValueError(f"policy missing or invalid action for state {name}")

        outcome = simulate_response(action, scenario)
        cost = calculate_response_cost(outcome, weights)

        results.append({
            "scenario_id": scenario["scenario_id"],
            "state_name": name,
            "action": action,
            "cost": cost,
            "residual_risk": outcome["residual_risk"],
            "service_availability": outcome["service_availability"],
            "recovery_minutes": outcome["recovery_minutes"],
        })

    n = len(results)
    return {
        "scenarios_evaluated": n,
        "mean_cost": round(sum(r["cost"] for r in results) / n, 4),
        "mean_residual_risk": round(
            sum(r["residual_risk"] for r in results) / n, 4
        ),
        "mean_service_availability": round(
            sum(r["service_availability"] for r in results) / n, 4
        ),
        "mean_recovery_minutes": round(
            sum(r["recovery_minutes"] for r in results) / n, 4
        ),
        "results": results,
    }


def fixed_policy(action: str) -> dict[str, Any]:
    """Build a policy that always chooses the same action."""
    if action not in ACTIONS:
        raise ValueError(f"Unknown action: {action}")
    return {
        "policy": {state_name(state): action for state in STATES}
    }