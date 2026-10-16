"""
Run robustness analysis on the held-out experiment.

Usage:
    python scripts\\analyse.py
    python scripts\\analyse.py --seeds 20 --episodes 20000
    python scripts\\analyse.py --quick
"""

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from aegis.experiment.analysis import run_seed_sweep, run_weight_sweep


WEIGHT_GRID = [
    {"residual_risk": 0.6, "availability_loss": 0.3, "recovery_time": 0.1},  # default
    {"residual_risk": 0.5, "availability_loss": 0.4, "recovery_time": 0.1},  # more availability-weighted
    {"residual_risk": 0.7, "availability_loss": 0.2, "recovery_time": 0.1},  # more risk-weighted
    {"residual_risk": 0.4, "availability_loss": 0.5, "recovery_time": 0.1},  # heavily availability-weighted
    {"residual_risk": 0.6, "availability_loss": 0.2, "recovery_time": 0.2},  # more recovery-weighted
]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--seeds", type=int, default=20)
    parser.add_argument("--training", type=int, default=1000)
    parser.add_argument("--test", type=int, default=250)
    parser.add_argument("--episodes", type=int, default=5000)
    parser.add_argument("--quick", action="store_true",
                        help="fast run for a sanity check")
    parser.add_argument("--out", type=str, default="results/analysis.json")
    args = parser.parse_args()

    if args.quick:
        args.seeds = 5
        args.training = 200
        args.test = 50
        args.episodes = 1000

    seed_list = list(range(1, args.seeds + 1))

    print(f"=== Seed sweep ({args.seeds} seeds) ===")
    seed_result = run_seed_sweep(
        seeds=seed_list,
        training_count=args.training,
        test_count=args.test,
        episodes=args.episodes,
    )
    s = seed_result["improvement_stats"]
    print(f"  improvement mean={s['mean']}% std={s['std']} "
          f"min={s['min']}% max={s['max']}%")
    print(f"  fraction of runs with positive improvement: "
          f"{seed_result['frac_runs_positive']:.2%}")
    print()

    print(f"=== Weight sweep ({len(WEIGHT_GRID)} configs, seed=42) ===")
    weight_result = run_weight_sweep(
        weight_grid=WEIGHT_GRID,
        training_count=args.training,
        test_count=args.test,
        episodes=args.episodes,
        seed=42,
    )
    w = weight_result["improvement_stats"]
    print(f"  improvement mean={w['mean']}% std={w['std']} "
          f"min={w['min']}% max={w['max']}%")
    print(f"  fraction of configs with positive improvement: "
          f"{weight_result['frac_configs_positive']:.2%}")
    for c in weight_result["per_config"]:
        weights = c["weights"]
        print(f"    {weights}  ->  {c['improvement_pct']:>7}% "
              f"(best baseline: {c['best_baseline']})")

    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps({
        "seed_sweep": seed_result,
        "weight_sweep": weight_result,
    }, indent=2), encoding="utf-8")
    print()
    print(f"Saved analysis to {out_path}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())