from fastapi.testclient import TestClient

from aegis.api.main import app


client = TestClient(app)


# --- health & graph ------------------------------------------------------

def test_health():
    r = client.get("/health")
    assert r.status_code == 200
    assert r.json() == {"status": "ok"}


def test_graph_summary():
    r = client.get("/graph")
    assert r.status_code == 200
    body = r.json()
    assert body["node_count"] > 0
    assert "identity:user:bob" in body["identities"]


def test_graph_paths_default_identity():
    r = client.get("/graph/paths")
    assert r.status_code == 200
    body = r.json()
    assert body["identity"] == "identity:user:bob"
    assert len(body["paths"]) >= 1
    assert "resource:customer-db" in body["reachable_resources"]


def test_graph_paths_rejects_non_identity():
    r = client.get("/graph/paths?identity=role:developer")
    assert r.status_code == 400


# --- pipeline ------------------------------------------------------------

def test_pipeline_run_returns_expected_shape():
    r = client.post("/pipeline/run", json={
        "event_count": 50,
        "seed": 42,
        "inject": ["brute_force", "privilege_escalation", "large_download"],
    })
    assert r.status_code == 200
    body = r.json()
    assert body["event_count"] >= 50
    assert body["alert_count"] >= 3
    assert body["incident_count"] >= 1
    assert body["scenario_count"] >= 1
    for scenario in body["scenarios"]:
        assert scenario["source_incident_id"].startswith("INC-")


def test_pipeline_run_rejects_unknown_injection():
    r = client.post("/pipeline/run", json={
        "event_count": 10,
        "seed": 1,
        "inject": ["not_a_real_pattern"],
    })
    assert r.status_code == 400


# --- experiment ----------------------------------------------------------

def test_experiment_run_returns_result():
    r = client.post("/experiment/run", json={
        "training_count": 100,
        "test_count": 20,
        "episodes": 200,
        "seed": 42,
    })
    assert r.status_code == 200
    body = r.json()
    assert "improvement_vs_best_baseline_pct" in body
    assert "learned_policy" in body
    assert len(body["learned_policy"]) == 9


def test_experiment_run_validation_rejects_zero():
    r = client.post("/experiment/run", json={
        "training_count": 0,
        "test_count": 20,
        "episodes": 200,
    })
    assert r.status_code == 422


def test_experiment_runs_list():
    r = client.get("/experiment/runs")
    assert r.status_code == 200
    assert "runs" in r.json()


def test_experiment_runs_detail_unknown():
    r = client.get("/experiment/runs/does-not-exist")
    assert r.status_code == 404
def test_graph_data_returns_nodes_and_edges():
    r = client.get("/graph/data")
    assert r.status_code == 200
    body = r.json()
    assert "nodes" in body
    assert "edges" in body
    assert len(body["nodes"]) > 0
    assert len(body["edges"]) > 0

    node_ids = {n["id"] for n in body["nodes"]}
    assert "identity:user:bob" in node_ids
    assert "resource:customer-db" in node_ids

    for edge in body["edges"]:
        assert edge["from"] in node_ids
        assert edge["to"] in node_ids