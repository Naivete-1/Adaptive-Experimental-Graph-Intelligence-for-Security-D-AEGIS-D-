import networkx as nx
import pytest

from aegis.attackgraph.graph import (
    add_edge,
    add_node,
    build_default_graph,
    classify_path_risk,
    contains_cycle,
    exposed_resources,
    find_attack_paths,
    identity_nodes,
    resource_nodes,
    sensitive_resources,
    summarise,
)


# --- construction --------------------------------------------------------

def test_default_graph_contains_expected_nodes():
    g = build_default_graph()
    summary = summarise(g)
    assert "identity:user:bob" in summary["identities"]
    assert "identity:user:alice" in summary["identities"]
    assert "role:cloud-admin" in summary["roles"]
    assert "service:deployment-api" in summary["services"]
    assert "resource:customer-db" in summary["resources"]


def test_default_graph_has_no_cycles():
    g = build_default_graph()
    assert not contains_cycle(g)


def test_add_node_rejects_unknown_kind():
    g = nx.DiGraph()
    with pytest.raises(ValueError):
        add_node(g, "gadget:thing")


def test_add_node_rejects_missing_kind_prefix():
    g = nx.DiGraph()
    with pytest.raises(ValueError):
        add_node(g, "no_colon_here")


def test_add_edge_validates_both_endpoints():
    g = nx.DiGraph()
    with pytest.raises(ValueError):
        add_edge(g, "gadget:thing", "role:developer")
    with pytest.raises(ValueError):
        add_edge(g, "role:developer", "gadget:thing")


# --- query helpers -------------------------------------------------------

def test_identity_and_resource_node_lists():
    g = build_default_graph()
    ids = identity_nodes(g)
    res = resource_nodes(g)
    assert "identity:user:bob" in ids
    assert "resource:customer-db" in res
    assert "role:developer" not in ids


def test_sensitive_resources_are_only_high_sensitivity():
    g = build_default_graph()
    sensitive = sensitive_resources(g)
    assert sensitive == ["resource:customer-db"]


# --- attack path finding -------------------------------------------------

def test_bob_can_reach_customer_db():
    g = build_default_graph()
    paths = find_attack_paths(g, "identity:user:bob")
    assert len(paths) >= 1
    longest = paths[-1]
    assert longest["target"] == "resource:customer-db"
    assert longest["path"][0] == "identity:user:bob"
    assert longest["path"][-1] == "resource:customer-db"


def test_bob_does_not_reach_any_resource_without_path():
    """
    In a graph where bob has no edges, no attack paths exist.
    """
    g = nx.DiGraph()
    add_node(g, "identity:user:bob")
    add_node(g, "resource:customer-db", sensitivity="high")
    paths = find_attack_paths(g, "identity:user:bob")
    assert paths == []


def test_find_attack_paths_rejects_unknown_source():
    g = build_default_graph()
    with pytest.raises(ValueError):
        find_attack_paths(g, "identity:user:nobody")


def test_find_attack_paths_rejects_non_identity_source():
    g = build_default_graph()
    with pytest.raises(ValueError):
        find_attack_paths(g, "role:developer")


def test_find_attack_paths_can_be_restricted_to_targets():
    g = build_default_graph()
    paths = find_attack_paths(
        g, "identity:user:bob",
        target_resources=["resource:public-dashboard"],
    )
    # bob cannot reach public-dashboard in the default graph.
    assert paths == []


# --- path classification -------------------------------------------------

def test_short_path_is_high_risk():
    g = build_default_graph()
    # Length 2 path (bob -> ... -> resource) with non-sensitive target
    path = ["identity:user:bob", "role:developer", "resource:analytics-dataset"]
    assert classify_path_risk(path, g) == "high"


def test_path_to_sensitive_resource_is_bumped():
    g = build_default_graph()
    # Length 4 (medium by default) reaching a sensitive resource → high.
    path = [
        "identity:user:bob",
        "role:developer",
        "service:deployment-api",
        "role:cloud-admin",
        "resource:customer-db",
    ]
    assert classify_path_risk(path, g) == "high"


# --- exposure ------------------------------------------------------------

def test_bob_can_reach_analytics_and_customer_db():
    g = build_default_graph()
    resources = exposed_resources(g, "identity:user:bob")
    assert "resource:customer-db" in resources
    assert "resource:analytics-dataset" in resources


def test_alice_only_reaches_public_dashboard():
    g = build_default_graph()
    resources = exposed_resources(g, "identity:user:alice")
    assert resources == ["resource:public-dashboard"]


def test_exposed_resources_rejects_non_identity():
    g = build_default_graph()
    with pytest.raises(ValueError):
        exposed_resources(g, "role:developer")


# --- summary -------------------------------------------------------------

def test_summary_counts_match_graph():
    g = build_default_graph()
    summary = summarise(g)
    assert summary["node_count"] == g.number_of_nodes()
    assert summary["edge_count"] == g.number_of_edges()
    assert summary["sensitive_resources"] == ["resource:customer-db"]