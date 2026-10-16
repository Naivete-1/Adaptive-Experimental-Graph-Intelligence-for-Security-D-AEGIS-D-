"""
Experiment persistence.

Every experiment is written to disk as a JSON file under
`results/experiments/`, and a summary row is appended to
`results/index.json`. This makes each run reproducible and auditable.

Design choices:
  * One file per run, named <timestamp>_seed<seed>.json.
  * An index file listing all runs, newest last.
  * Callers can pass an explicit base_dir, which makes the module
    testable against a temporary directory.
"""

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


DEFAULT_BASE_DIR = Path("results")
EXPERIMENTS_SUBDIR = "experiments"
INDEX_FILENAME = "index.json"


def _ensure_dirs(base_dir: Path) -> Path:
    experiments_dir = base_dir / EXPERIMENTS_SUBDIR
    experiments_dir.mkdir(parents=True, exist_ok=True)
    return experiments_dir


def _run_id(seed: int, when: datetime) -> str:
    return f"{when.strftime('%Y%m%dT%H%M%SZ')}_seed{seed}"


def save_experiment(
    result: dict[str, Any],
    *,
    base_dir: Path | str = DEFAULT_BASE_DIR,
    label: str | None = None,
) -> dict[str, Any]:
    """
    Persist an experiment result.

    Returns a small metadata dict:
      {run_id, path, saved_at, seed, label}

    `result` is expected to be the output of run_experiment(), but this
    function does not require a specific shape — it only reads `seed`
    from result["config"] if present, for the filename.
    """
    if not isinstance(result, dict):
        raise ValueError("result must be a dictionary")

    base = Path(base_dir)
    experiments_dir = _ensure_dirs(base)

    seed = 0
    config = result.get("config")
    if isinstance(config, dict) and isinstance(config.get("seed"), int):
        seed = config["seed"]

    now = datetime.now(timezone.utc)
    run_id = _run_id(seed, now)

    run_path = experiments_dir / f"{run_id}.json"
    if run_path.exists():
        # Extremely unlikely (same second + same seed), but be safe.
        run_id = f"{run_id}_{now.microsecond}"
        run_path = experiments_dir / f"{run_id}.json"

    payload = {
        "run_id": run_id,
        "saved_at": now.isoformat(),
        "label": label,
        "result": result,
    }
    run_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")

    # Append to index.
    index_path = base / INDEX_FILENAME
    index = _read_index(index_path)

    improvement = result.get("improvement_vs_best_baseline_pct")
    learned_cost = None
    evaluations = result.get("evaluations")
    if isinstance(evaluations, dict):
        learned = evaluations.get("learned_policy")
        if isinstance(learned, dict):
            learned_cost = learned.get("mean_cost")

    index["runs"].append({
        "run_id": run_id,
        "saved_at": now.isoformat(),
        "label": label,
        "seed": seed,
        "improvement_vs_best_baseline_pct": improvement,
        "learned_mean_cost": learned_cost,
        "path": str(run_path),
    })
    index_path.write_text(json.dumps(index, indent=2), encoding="utf-8")

    return {
        "run_id": run_id,
        "path": str(run_path),
        "saved_at": now.isoformat(),
        "seed": seed,
        "label": label,
    }


def _read_index(index_path: Path) -> dict[str, Any]:
    if not index_path.exists():
        return {"runs": []}
    try:
        data = json.loads(index_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        # Don't lose history silently; back up the broken file.
        backup = index_path.with_suffix(".broken.json")
        index_path.replace(backup)
        return {"runs": []}
    if not isinstance(data, dict) or "runs" not in data:
        return {"runs": []}
    return data


def load_experiment(
    run_id: str,
    *,
    base_dir: Path | str = DEFAULT_BASE_DIR,
) -> dict[str, Any]:
    """Load a previously saved experiment by run_id."""
    base = Path(base_dir)
    run_path = base / EXPERIMENTS_SUBDIR / f"{run_id}.json"
    if not run_path.exists():
        raise FileNotFoundError(f"No experiment found with run_id: {run_id}")
    return json.loads(run_path.read_text(encoding="utf-8"))


def list_experiments(
    *,
    base_dir: Path | str = DEFAULT_BASE_DIR,
) -> list[dict[str, Any]]:
    """Return the list of runs recorded in the index."""
    base = Path(base_dir)
    return _read_index(base / INDEX_FILENAME)["runs"]