"""
FastAPI application exposing the AEGIS-D pipeline.

Endpoints cover three areas:
  * attack graph inspection (summary, raw data, path queries)
  * the detection pipeline (events → alerts → incidents → scenarios)
  * the held-out RL experiment

The root path serves a dashboard for manual use. Static assets (CSS, JS)
are served from /static.
"""

from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from aegis.attackgraph.graph import (
    build_default_graph,
    exposed_resources,
    find_attack_paths,
    summarise,
    to_vis_data,
)
from aegis.chronicle.bridge import incidents_to_scenarios
from aegis.chronicle.correlator import correlate_alerts
from aegis.events.generator import generate_events
from aegis.experiment.persistance import list_experiments, load_experiment
from aegis.experiment.runner import run_experiment
from aegis.sentinel.rules import run_rules


PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent.parent
FRONTEND_DIR = PROJECT_ROOT / "frontend"
FRONTEND_INDEX = FRONTEND_DIR / "index.html"


app = FastAPI(title="AEGIS-D", version="0.2.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],     # local development only
    allow_methods=["*"],
    allow_headers=["*"],
)

if FRONTEND_DIR.exists():
    app.mount("/static", StaticFiles(directory=FRONTEND_DIR), name="static")


# --- request models ------------------------------------------------------

class ExperimentRequest(BaseModel):
    training_count: int = Field(default=1000, ge=1, le=100_000)
    test_count: int = Field(default=250, ge=1, le=100_000)
    episodes: int = Field(default=5000, ge=1, le=1_000_000)
    seed: int = Field(default=42)


class PipelineRequest(BaseModel):
    event_count: int = Field(default=100, ge=1, le=10_000)
    seed: int = Field(default=42)
    inject: list[str] = Field(
        default_factory=lambda: [
            "brute_force",
            "privilege_escalation",
            "large_download",
        ]
    )


# --- endpoints -----------------------------------------------------------

@app.get("/", response_class=HTMLResponse)
def dashboard() -> HTMLResponse:
    if not FRONTEND_INDEX.exists():
        return HTMLResponse("<h1>AEGIS-D</h1><p>Dashboard not found.</p>")
    return HTMLResponse(FRONTEND_INDEX.read_text(encoding="utf-8"))


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/graph")
def get_graph() -> dict[str, Any]:
    return summarise(build_default_graph())


@app.get("/graph/data")
def get_graph_data() -> dict[str, Any]:
    """Nodes and edges of the default attack graph, for visualisation."""
    return to_vis_data(build_default_graph())


@app.get("/graph/paths")
def get_paths(identity: str = "identity:user:bob") -> dict[str, Any]:
    graph = build_default_graph()
    try:
        paths = find_attack_paths(graph, identity)
        reachable = exposed_resources(graph, identity)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    return {
        "identity": identity,
        "paths": paths,
        "reachable_resources": reachable,
    }


@app.post("/pipeline/run")
def pipeline_run(req: PipelineRequest) -> dict[str, Any]:
    try:
        events = generate_events(
            count=req.event_count,
            seed=req.seed,
            inject=tuple(req.inject),
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    alerts = run_rules(events)
    incidents = correlate_alerts(alerts, events)
    graph = build_default_graph()
    scenarios = incidents_to_scenarios(incidents, graph=graph)

    return {
        "event_count": len(events),
        "alert_count": len(alerts),
        "alerts": alerts,
        "incident_count": len(incidents),
        "incidents": [
            {k: v for k, v in inc.items() if k != "events"}
            for inc in incidents
        ],
        "scenario_count": len(scenarios),
        "scenarios": scenarios,
    }


@app.post("/experiment/run")
def experiment_run(req: ExperimentRequest) -> dict[str, Any]:
    return run_experiment(
        training_count=req.training_count,
        test_count=req.test_count,
        episodes=req.episodes,
        seed=req.seed,
    )


@app.get("/experiment/runs")
def experiment_runs() -> dict[str, Any]:
    return {"runs": list_experiments()}


@app.get("/experiment/runs/{run_id}")
def experiment_run_detail(run_id: str) -> dict[str, Any]:
    try:
        return load_experiment(run_id)
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail=f"run not found: {run_id}")