"""
AttackGraph — modelling potential attack paths.

A directed graph whose nodes are identities, roles, services, and
resources, and whose edges represent assumed access relationships.

The graph is *not* a verified permission model. It represents
relationships an operator has declared or that a discovery tool has
observed. Attack paths through the graph are hypotheses worth
investigating, not confirmed routes.

Node naming convention:
    identity:user:bob
    role:developer
    service:deployment-api
    resource:customer-db
"""

import networkx as nx
from typing import Any


NODE_KINDS = ("identity", "role", "service", "resource")


# --- Node helpers ---------------------------------------------------------

def _kind_of(node_id: str) -> str:
    if ":" not in node_id:
        raise ValueError(f"node id must be '<kind>:<name>': {node_id!r}")
    return node_id.split(":", 1)[0]


def _validate_node(node_id: str) -> None:
    kind = _kind_of(node_id)
    if kind not in NODE_KINDS:
        raise ValueError(f"unknown node kind {kind!r} in {node_id!r}")


# --- Construction ---------------------------------------------------------

def add_node(graph: nx.DiGraph, node_id: str, **attrs: Any) -> None:
    _validate_node(node_id)
    graph.add_node(node_id, kind=_kind_of(node_id), **attrs)


def add_edge(graph: nx.DiGraph, source: str, target: str, **attrs: Any) -> None:
    _validate_node(source)
    _validate_node(target)
    graph.add_edge(source, target, **attrs)


def build_default_graph() -> nx.DiGraph:
    """
    Illustrative graph used for tests and demos.

    Path:
        user:bob → role:developer → service:deployment-api
                 → role:cloud-admin → resource:customer-db

    This mirrors the example in the project documentation. Edges are
    assumed, not verified.
    """
    g = nx.DiGraph()

    add_node(g, "identity:user:bob", label="Bob")
    add_node(g, "identity:user:alice", label="Alice")
    add_node(g, "role:developer", label="Developer role")
    add_node(g, "role:cloud-admin", label="Cloud admin role")
    add_node(g, "service:deployment-api", label="Deployment API")
    add_node(g, "resource:customer-db", label="Customer database",
             sensitivity="high")
    add_node(g, "resource:analytics-dataset", label="Analytics dataset",
             sensitivity="medium")
    add_node(g, "resource:public-dashboard", label="Public dashboard",
             sensitivity="low")

    # Path that reaches the sensitive resource.
    add_edge(g, "identity:user:bob", "role:developer", relation="assigned")
    add_edge(g, "role:developer", "service:deployment-api", relation="access")
    add_edge(g, "service:deployment-api", "role:cloud-admin",
             relation="can_assume")
    add_edge(g, "role:cloud-admin", "resource:customer-db", relation="read")

    # A benign branch.
    add_edge(g, "identity:user:alice", "resource:public-dashboard",
             relation="read")
    add_edge(g, "role:developer", "resource:analytics-dataset",
             relation="read")

    return g


# --- Analysis -------------------------------------------------------------

def identity_nodes(graph: nx.DiGraph) -> list[str]:
    return [n for n, d in graph.nodes(data=True) if d.get("kind") == "identity"]


def resource_nodes(graph: nx.DiGraph) -> list[str]:
    return [n for n, d in graph.nodes(data=True) if d.get("kind") == "resource"]


def sensitive_resources(graph: nx.DiGraph) -> list[str]:
    return [
        n for n, d in graph.nodes(data=True)
        if d.get("kind") == "resource" and d.get("sensitivity") == "high"
    ]


def find_attack_paths(
    graph: nx.DiGraph,
    source_identity: str,
    target_resources: list[str] | None = None,
    *,
    max_length: int = 6,
) -> list[dict[str, Any]]:
    """
    Find directed paths from an identity to any sensitive resource.

    Returns a list of path records, each containing the node sequence,
    the target resource, path length, and a risk classification.
    """
    if source_identity not in graph:
        raise ValueError(f"source identity not in graph: {source_identity}")
    if _kind_of(source_identity) != "identity":
        raise ValueError(f"source must be an identity node: {source_identity}")

    targets = target_resources or sensitive_resources(graph)

    paths: list[dict[str, Any]] = []
    for target in targets:
        if target not in graph:
            continue
        try:
            for path in nx.all_simple_paths(
                graph, source_identity, target, cutoff=max_length
            ):
                paths.append({
                    "source": source_identity,
                    "target": target,
                    "path": path,
                    "length": len(path) - 1,
                    "risk": classify_path_risk(path, graph),
                })
        except nx.NetworkXNoPath:
            continue

    paths.sort(key=lambda p: (p["length"], p["target"]))
    return paths


def classify_path_risk(path: list[str], graph: nx.DiGraph) -> str:
    """
    Heuristic risk label for one attack path.

    Rules (documented, not empirically validated):
      * The target resource's declared sensitivity is the base risk.
      * Short paths (length ≤ 2) are bumped one level: easier to traverse.
      * Long paths (length ≥ 5) are dropped one level: more failure points
        for an attacker.

    Sensitivity dominates; path length only modulates. A long path to a
    critical resource is still high-risk — it just took more steps to
    reach.
    """
    order = ["low", "medium", "high"]

    target_attrs = graph.nodes.get(path[-1], {})
    target_sensitivity = target_attrs.get("sensitivity", "medium")
    base_idx = order.index(target_sensitivity)

    length = len(path) - 1
    if length <= 2:
        base_idx = min(base_idx + 1, len(order) - 1)
    elif length >= 5:
        base_idx = max(base_idx - 1, 0)

    return order[base_idx]
def exposed_resources(
    graph: nx.DiGraph,
    source_identity: str,
    *,
    max_length: int = 6,
) -> list[str]:
    """
    Return the set of resources reachable from an identity, regardless of
    sensitivity. Useful for "what could this identity touch?" queries.
    """
    if source_identity not in graph:
        raise ValueError(f"identity not in graph: {source_identity}")
    if _kind_of(source_identity) != "identity":
        raise ValueError(f"source must be an identity node: {source_identity}")

    reachable: set[str] = set()
    for target in resource_nodes(graph):
        if target == source_identity:
            continue
        if nx.has_path(graph, source_identity, target):
            try:
                length = nx.shortest_path_length(graph, source_identity, target)
            except nx.NetworkXNoPath:
                continue
            if length <= max_length:
                reachable.add(target)
    return sorted(reachable)


def summarise(graph: nx.DiGraph) -> dict[str, Any]:
    """A short human-readable summary of the graph."""
    kinds = {"identity": [], "role": [], "service": [], "resource": []}
    for node, attrs in graph.nodes(data=True):
        kind = attrs.get("kind")
        if kind in kinds:
            kinds[kind].append(node)

    return {
        "node_count": graph.number_of_nodes(),
        "edge_count": graph.number_of_edges(),
        "identities": sorted(kinds["identity"]),
        "roles": sorted(kinds["role"]),
        "services": sorted(kinds["service"]),
        "resources": sorted(kinds["resource"]),
        "sensitive_resources": sorted(sensitive_resources(graph)),
    }


def contains_cycle(graph: nx.DiGraph) -> bool:
    """Convenience wrapper for tests and diagnostics."""
    return not nx.is_directed_acyclic_graph(graph)
def to_vis_data(graph: nx.DiGraph) -> dict[str, list[dict[str, Any]]]:
    """
    Serialise the graph into a nodes/edges structure suitable for the
    frontend visualisation library (vis-network).
    """
    nodes: list[dict[str, Any]] = []
    for node_id, attrs in graph.nodes(data=True):
        nodes.append({
            "id": node_id,
            "label": attrs.get("label", node_id.split(":", 1)[-1]),
            "kind": attrs.get("kind"),
            "sensitivity": attrs.get("sensitivity"),
        })

    edges: list[dict[str, Any]] = []
    for source, target, attrs in graph.edges(data=True):
        edges.append({
            "from": source,
            "to": target,
            "relation": attrs.get("relation", ""),
        })

    return {"nodes": nodes, "edges": edges}