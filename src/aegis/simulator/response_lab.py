"""
Response Lab — simulated outcome model for response strategies.

The outcome of a response depends on BOTH the strategy and the scenario's
features. Every modulation below is a documented assumption, not a
measured real-world result.
"""

from typing import Any


# ---------------------------------------------------------------------------
# Base response characteristics, before scenario modulation.
# ---------------------------------------------------------------------------

RESPONSE_MODELS: dict[str, dict[str, Any]] = {
    "disable_identity": {
        "risk_reduction": 85.0,
        "availability_loss": 35.0,
        "recovery_minutes": 60.0,
        "description": "Disable the suspected compromised identity",
    },
    "isolate_service": {
        "risk_reduction": 70.0,
        "availability_loss": 20.0,
        "recovery_minutes": 35.0,
        "description": "Isolate the affected deployment service",
    },
    "revoke_privilege": {
        "risk_reduction": 55.0,
        "availability_loss": 5.0,
        "recovery_minutes": 15.0,
        "description": "Revoke elevated privileges from the identity",
    },
}

ACTIONS = tuple(RESPONSE_MODELS.keys())


# ---------------------------------------------------------------------------
# Modulation tables.
# ---------------------------------------------------------------------------

# How attack type scales the base risk_reduction of each strategy.
ATTACK_TYPE_RISK_FACTOR = {
    "brute_force": {
        "disable_identity": 1.10,
        "isolate_service": 0.85,
        "revoke_privilege": 0.70,
    },
    "privilege_escalation": {
        "disable_identity": 0.95,
        "isolate_service": 0.90,
        "revoke_privilege": 1.15,
    },
    "data_exfiltration": {
        "disable_identity": 0.80,
        "isolate_service": 1.15,
        "revoke_privilege": 0.75,
    },
}

# How detection confidence scales achievable risk_reduction.
DETECTION_CONFIDENCE_RISK_FACTOR = {
    "low": 0.60,
    "medium": 0.85,
    "high": 1.00,
}

# How compromise scope scales achievable risk_reduction per strategy.
COMPROMISE_SCOPE_RISK_FACTOR = {
    "single_identity": {
        "disable_identity": 1.05,
        "isolate_service": 0.95,
        "revoke_privilege": 1.05,
    },
    "multiple_identities": {
        "disable_identity": 0.75,
        "isolate_service": 0.90,
        "revoke_privilege": 0.80,
    },
    "service_affected": {
        "disable_identity": 0.90,
        "isolate_service": 1.10,
        "revoke_privilege": 0.85,
    },
}

# How asset criticality scales availability loss and recovery time.
CRITICALITY_AVAILABILITY_FACTOR = {"low": 0.7, "medium": 1.0, "high": 1.4}
CRITICALITY_RECOVERY_FACTOR = {"low": 0.9, "medium": 1.0, "high": 1.2}


# ---------------------------------------------------------------------------
# Cost model.
# ---------------------------------------------------------------------------

COST_WEIGHTS = {
    "residual_risk": 0.6,
    "availability_loss": 0.3,
    "recovery_time": 0.1,
}

MAX_RECOVERY_MINUTES = 120.0


# ---------------------------------------------------------------------------
# Helpers.
# ---------------------------------------------------------------------------

def _require_scenario_fields(scenario: dict) -> None:
    for field in ("scenario_id", "initial_risk", "initial_availability"):
        if field not in scenario:
            raise ValueError(f"Scenario is missing required field: {field}")

    for field in ("initial_risk", "initial_availability"):
        value = scenario[field]
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            raise ValueError(f"{field} must be numeric")
        if not 0 <= value <= 100:
            raise ValueError(f"{field} must be between 0 and 100")


def _factor(table: dict, key: Any, strategy: str | None = None) -> float:
    """Look up a modulation factor; return 1.0 if the feature is absent."""
    if key is None:
        return 1.0
    row = table[key]
    if strategy is None:
        return float(row)
    return float(row[strategy])


# ---------------------------------------------------------------------------
# Core simulation.
# ---------------------------------------------------------------------------

def simulate_response(
    strategy: str,
    scenario: dict,
    weights: dict | None = None,
) -> dict:
    """Simulate the assumed outcome of one response strategy."""
    if strategy not in RESPONSE_MODELS:
        raise ValueError(f"Unknown response strategy: {strategy}")
    if not isinstance(scenario, dict):
        raise ValueError("scenario must be a dictionary")

    _require_scenario_fields(scenario)

    base = RESPONSE_MODELS[strategy]
    initial_risk = float(scenario["initial_risk"])
    initial_availability = float(scenario["initial_availability"])

    attack_type = scenario.get("attack_type")
    criticality = scenario.get("criticality")
    detection_confidence = scenario.get("detection_confidence")
    compromise_scope = scenario.get("compromise_scope")

    risk_reduction = base["risk_reduction"]
    risk_reduction *= _factor(ATTACK_TYPE_RISK_FACTOR, attack_type, strategy)
    risk_reduction *= _factor(DETECTION_CONFIDENCE_RISK_FACTOR, detection_confidence)
    risk_reduction *= _factor(COMPROMISE_SCOPE_RISK_FACTOR, compromise_scope, strategy)
    risk_reduction = max(0.0, min(100.0, risk_reduction))

    availability_loss = base["availability_loss"]
    availability_loss *= _factor(CRITICALITY_AVAILABILITY_FACTOR, criticality)
    availability_loss = max(0.0, min(100.0, availability_loss))

    recovery_minutes = base["recovery_minutes"]
    recovery_minutes *= _factor(CRITICALITY_RECOVERY_FACTOR, criticality)

    risk_reduction = min(initial_risk, risk_reduction)
    availability_loss = min(initial_availability, availability_loss)

    residual_risk = initial_risk - risk_reduction
    availability = initial_availability - availability_loss

    outcome = {
        "scenario_id": scenario["scenario_id"],
        "strategy": strategy,
        "description": base["description"],
        "initial_risk": initial_risk,
        "residual_risk": residual_risk,
        "risk_reduction": risk_reduction,
        "initial_availability": initial_availability,
        "service_availability": availability,
        "availability_loss": availability_loss,
        "recovery_minutes": recovery_minutes,
        "scenario_features_used": {
            "attack_type": attack_type,
            "criticality": criticality,
            "detection_confidence": detection_confidence,
            "compromise_scope": compromise_scope,
        },
        "assumption_based": True,
        "environment": "simulated",
    }
    outcome["decision_score"] = calculate_response_cost(outcome, weights)
    return outcome


# ---------------------------------------------------------------------------
# Cost.
# ---------------------------------------------------------------------------

def calculate_response_cost(
    outcome: dict,
    weights: dict | None = None,
) -> float:
    """Lower is better. Combines residual risk, availability loss, recovery."""
    for field in ("residual_risk", "availability_loss", "recovery_minutes"):
        if field not in outcome:
            raise ValueError(f"Outcome is missing required field: {field}")

    w = weights if weights is not None else COST_WEIGHTS

    residual_risk = outcome["residual_risk"]
    availability_loss = outcome["availability_loss"]
    recovery_minutes = outcome["recovery_minutes"]

    for name, value in (
        ("residual_risk", residual_risk),
        ("availability_loss", availability_loss),
    ):
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            raise ValueError(f"{name} must be numeric")
        if not 0 <= value <= 100:
            raise ValueError(f"{name} must be between 0 and 100")

    if (
        isinstance(recovery_minutes, bool)
        or not isinstance(recovery_minutes, (int, float))
        or recovery_minutes < 0
    ):
        raise ValueError("recovery_minutes must be a non-negative number")

    recovery_score = (
        min(recovery_minutes, MAX_RECOVERY_MINUTES) / MAX_RECOVERY_MINUTES * 100
    )

    cost = (
        w["residual_risk"] * residual_risk
        + w["availability_loss"] * availability_loss
        + w["recovery_time"] * recovery_score
    )
    return round(cost, 4)


# ---------------------------------------------------------------------------
# Comparison across strategies for one scenario.
# ---------------------------------------------------------------------------

def compare_strategies(scenario: dict) -> dict:
    """Evaluate and rank every strategy for a single scenario."""
    outcomes = [simulate_response(action, scenario) for action in ACTIONS]
    ranked = sorted(outcomes, key=lambda o: o["decision_score"])

    return {
        "scenario_id": scenario["scenario_id"],
        "recommended_strategy": ranked[0]["strategy"],
        "ranked": ranked,
        "cost_weights": dict(COST_WEIGHTS),
        "method": "scenario_aware_simulated_outcome_model",
    }