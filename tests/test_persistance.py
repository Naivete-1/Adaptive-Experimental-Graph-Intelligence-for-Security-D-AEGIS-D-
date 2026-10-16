import json
from pathlib import Path

import pytest

from aegis.experiment.persistance import (
    list_experiments,
    load_experiment,
    save_experiment,
)


def _fake_result(seed=42, improvement=5.5, learned_cost=9.0):
    return {
        "config": {"training_count": 100, "test_count": 20,
                   "episodes": 200, "seed": seed},
        "learned_policy": {"low_severity_low_criticality": "revoke_privilege"},
        "evaluations": {
            "learned_policy": {"mean_cost": learned_cost},
        },
        "improvement_vs_best_baseline_pct": improvement,
    }


def test_save_writes_run_file(tmp_path):
    meta = save_experiment(_fake_result(), base_dir=tmp_path)
    run_path = Path(meta["path"])
    assert run_path.exists()

    payload = json.loads(run_path.read_text(encoding="utf-8"))
    assert payload["run_id"] == meta["run_id"]
    assert payload["result"]["config"]["seed"] == 42
    assert payload["label"] is None


def test_save_appends_to_index(tmp_path):
    save_experiment(_fake_result(seed=1), base_dir=tmp_path)
    save_experiment(_fake_result(seed=2), base_dir=tmp_path)

    runs = list_experiments(base_dir=tmp_path)
    assert len(runs) == 2
    assert runs[0]["seed"] == 1
    assert runs[1]["seed"] == 2


def test_save_records_label(tmp_path):
    meta = save_experiment(_fake_result(), base_dir=tmp_path, label="baseline-run")
    assert meta["label"] == "baseline-run"

    runs = list_experiments(base_dir=tmp_path)
    assert runs[0]["label"] == "baseline-run"


def test_save_records_improvement_and_learned_cost(tmp_path):
    save_experiment(_fake_result(improvement=7.25, learned_cost=8.5),
                    base_dir=tmp_path)
    runs = list_experiments(base_dir=tmp_path)
    assert runs[0]["improvement_vs_best_baseline_pct"] == 7.25
    assert runs[0]["learned_mean_cost"] == 8.5


def test_load_round_trips(tmp_path):
    meta = save_experiment(_fake_result(seed=99), base_dir=tmp_path)
    loaded = load_experiment(meta["run_id"], base_dir=tmp_path)
    assert loaded["result"]["config"]["seed"] == 99


def test_load_unknown_run_raises(tmp_path):
    with pytest.raises(FileNotFoundError):
        load_experiment("does-not-exist", base_dir=tmp_path)


def test_list_on_empty_dir_returns_empty(tmp_path):
    assert list_experiments(base_dir=tmp_path) == []


def test_corrupt_index_is_recovered(tmp_path):
    # Break the index file.
    (tmp_path / "index.json").write_text("not json", encoding="utf-8")
    save_experiment(_fake_result(), base_dir=tmp_path)

    # Original should have been backed up, new index should be valid.
    assert (tmp_path / "index.broken.json").exists()
    runs = list_experiments(base_dir=tmp_path)
    assert len(runs) == 1


def test_save_rejects_non_dict(tmp_path):
    with pytest.raises(ValueError):
        save_experiment("not-a-dict", base_dir=tmp_path)


def test_full_experiment_round_trip(tmp_path):
    """
    Integration: run the actual experiment, save it, load it back, and
    confirm the improvement number survives the round trip.
    """
    from aegis.experiment.runner import run_experiment

    result = run_experiment(
        training_count=100, test_count=20, episodes=200, seed=42
    )
    meta = save_experiment(result, base_dir=tmp_path)
    loaded = load_experiment(meta["run_id"], base_dir=tmp_path)

    assert (loaded["result"]["improvement_vs_best_baseline_pct"]
            == result["improvement_vs_best_baseline_pct"])
    assert loaded["result"]["config"]["seed"] == 42