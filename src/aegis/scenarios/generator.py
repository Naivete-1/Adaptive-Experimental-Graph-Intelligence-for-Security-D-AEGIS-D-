"""
Scenario generator.

Produces reproducible synthetic security scenarios that can be passed
directly to the simulator. Each scenario carries the features the
simulator uses to modulate response outcomes, plus an initial_risk
derived from severity.
"""

import random
from typing import Any


SEVERITIES = ("low", "medium", "high")
CRITICALITIES = ("low", "medium", "high")
ATTACK_TYPES = ("brute_force", "privilege_escalation", "data_exfiltration")
DETECTION_CONFIDENCE = ("low", "medium", "high")
COMPROMISE_SCOPES = ("single_identity", "multiple_identities", "service_affected")

SEVERITY_INITIAL_RISK = {"low": 30, "medium": 60, "high": 90}
DEFAULT_INITIAL_AVAILABILITY = 100


def generate_scenarios(count: int = 1000, seed: int = 42) -> list[dict[str, Any]]:
    """Generate a list of reproducible synthetic scenarios."""
    if isinstance(count, bool) or not isinstance(count, int) or count < 1:
        raise ValueError("count must be a positive integer")

    if isinstance(seed, bool) or not isinstance(seed, int):
        raise ValueError("seed must be an integer")

    rng = random.Random(seed)
    scenarios: list[dict[str, Any]] = []

    for index in range(1, count + 1):
        severity = rng.choice(SEVERITIES)
        scenarios.append({
            "scenario_id": f"SCN-{seed}-{index:05d}",
            "severity": severity,
            "criticality": rng.choice(CRITICALITIES),
            "attack_type": rng.choice(ATTACK_TYPES),
            "detection_confidence": rng.choice(DETECTION_CONFIDENCE),
            "compromise_scope": rng.choice(COMPROMISE_SCOPES),
            "initial_risk": SEVERITY_INITIAL_RISK[severity],
            "initial_availability": DEFAULT_INITIAL_AVAILABILITY,
            "seed": seed,
            "environment": "simulated",
        })

    return scenarios