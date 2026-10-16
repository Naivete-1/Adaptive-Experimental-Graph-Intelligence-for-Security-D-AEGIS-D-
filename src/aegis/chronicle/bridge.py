"""
Bridge from detected incidents (Chronicle) to scenarios (simulator).

An incident describes what was observed. A scenario describes what the
response agent needs to decide. This module maps one to the other with
explicit, documented rules.

Criticality derivation has two modes:

  * Resource-based (default). Uses SENSITIVE_RESOURCES as a stand-in for
    an asset inventory. Applies when no attack graph is supplied.

  * Graph-based (preferred). Uses `attackgraph.graph.exposed_resources`
    to ask "what can this compromised identity reach?" rather than
    "what resources appear in the incident's events?". Applies when a
    NetworkX attack graph is passed in.

Every mapping below is a modelling assumption, not a measured fact.
"""

from typing import Any

import networkx as nx

from aegis.attackgraph.graph import exposed_resources


# --- Mapping tables -------------------------------------------------------

RULE_TO_ATTACK_TYPE = {
    "brute_force": "brute_force",
    "privilege_escalation": "privilege_escalation",
    "large_download": "data_exfiltration",
}

RULE_PRIORITY = {
    "privilege_escalation": 3,
    "large_download": 2,
    "brute_force": 1,
}

# Fallback asset inventory. Used when no attack graph is supplied, or
# when a resource appears in an event but not in the graph.
SENSITIVE_RESOURCES = {
    "dataset:customer-pii": "high",
    "log:audit": "medium",
    "dataset:analytics": "medium",
    "report:weekly": "low",
}
DEFAULT_CRITICALITY = "medium"

DEFAULT_INITIAL_AVAILABILITY = 100

SEVERITY_INITIAL_RISK = {"low": 30, "medium": 60, "high": 90}

_CRITICALITY_ORDER = {"low": 0, "medium": 1, "high": 2}


# --- Derivation helpers ---------------------------------------------------

def _derive_attack_type(rule_names: list[str]) -> str:
    if not rule_names:
        return "brute_force"
    highest = max(rule_names, key=lambda r: RULE_PRIORITY.get(r, 0))
    return RULE_TO_ATTACK_TYPE.get(highest, "brute_force")


def _criticality_from_resources(
    events: list[dict[str, Any]],
) -> str | None:
    """
    Name-lookup criticality from the resources referenced by events.

    Returns None if no event references a known resource; the caller
    then falls through to the default.
    """
    best: str | None = None
    for event in events:
        resource = event.get("resource")
        if resource in SENSITIVE_RESOURCES:
            candidate = SENSITIVE_RESOURCES[resource]
            if best is None or _CRITICALITY_ORDER[candidate] > _CRITICALITY_ORDER[best]:
                best = candidate
    return best


def _identity_node(user: str, graph: nx.DiGraph) -> str | None:
    """
    Map an incident's user string to a graph node id, if one exists.

    Convention: users appear in incidents as "user:bob"; the graph uses
    "identity:user:bob". We try the direct form first, then the identity
    prefix.
    """
    candidates = [user]
    if not user.startswith("identity:"):
        candidates.append(f"identity:{user}")
    for candidate in candidates:
        if candidate in graph:
            return candidate
    return None


def _criticality_from_graph(
    user: str,
    graph: nx.DiGraph,
) -> str | None:
    """
    Reachability-based criticality.

    Returns the maximum criticality among resources the identity can
    reach, or None if the identity is not in the graph or reaches no
    classified resource.
    """
    identity = _identity_node(user, graph)
    if identity is None:
        return None

    try:
        reachable = exposed_resources(graph, identity)
    except ValueError:
        return None

    best: str | None = None
    for node in reachable:
        sensitivity = graph.nodes.get(node, {}).get("sensitivity")
        if sensitivity in _CRITICALITY_ORDER:
            if best is None or _CRITICALITY_ORDER[sensitivity] > _CRITICALITY_ORDER[best]:
                best = sensitivity
    return best


def _derive_criticality(
    incident: dict[str, Any],
    graph: nx.DiGraph | None,
) -> str:
    """
    Determine criticality.

    Order of preference:
      1. Attack-graph reachability (if a graph is provided and the
         identity is known to it).
      2. Resource-name lookup from the incident's events.
      3. DEFAULT_CRITICALITY.
    """
    if graph is not None:
        from_graph = _criticality_from_graph(incident["user"], graph)
        if from_graph is not None:
            return from_graph

    from_resources = _criticality_from_resources(incident["events"])
    if from_resources is not None:
        return from_resources

    return DEFAULT_CRITICALITY


def _bin_confidence(confidence: float) -> str:
    if confidence < 0.5:
        return "low"
    if confidence < 0.8:
        return "medium"
    return "high"


def _derive_scope(rule_names: list[str]) -> str:
    n = len(set(rule_names))
    if n <= 1:
        return "single_identity"
    if n == 2:
        return "multiple_identities"
    return "service_affected"


# --- Public API -----------------------------------------------------------

def incident_to_scenario(
    incident: dict[str, Any],
    graph: nx.DiGraph | None = None,
) -> dict[str, Any]:
    """
    Convert one incident into one scenario suitable for the simulator.

    If `graph` is provided, criticality is derived from what the
    incident's user can reach in the attack graph. Otherwise, it falls
    back to a name lookup against SENSITIVE_RESOURCES.
    """
    if not isinstance(incident, dict):
        raise ValueError("incident must be a dictionary")

    for field in ("incident_id", "severity", "rule_names", "confidence", "events"):
        if field not in incident:
            raise ValueError(f"incident missing required field: {field}")

    severity = incident["severity"]
    if severity not in SEVERITY_INITIAL_RISK:
        raise ValueError(f"incident has invalid severity: {severity!r}")

    attack_type = _derive_attack_type(incident["rule_names"])
    criticality = _derive_criticality(incident, graph)
    detection_confidence = _bin_confidence(incident["confidence"])
    compromise_scope = _derive_scope(incident["rule_names"])

    return {
        "scenario_id": f"SCN-FROM-{incident['incident_id']}",
        "severity": severity,
        "criticality": criticality,
        "attack_type": attack_type,
        "detection_confidence": detection_confidence,
        "compromise_scope": compromise_scope,
        "initial_risk": SEVERITY_INITIAL_RISK[severity],
        "initial_availability": DEFAULT_INITIAL_AVAILABILITY,
        "source_incident_id": incident["incident_id"],
        "environment": "simulated",
    }


def incidents_to_scenarios(
    incidents: list[dict[str, Any]],
    graph: nx.DiGraph | None = None,
) -> list[dict[str, Any]]:
    """Convert a list of incidents into a list of scenarios."""
    if not isinstance(incidents, list):
        raise ValueError("incidents must be a list")
    return [incident_to_scenario(inc, graph) for inc in incidents]