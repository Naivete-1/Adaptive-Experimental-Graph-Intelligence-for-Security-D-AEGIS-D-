"""
Run an AEGIS-D held-out experiment from the command line and save it.

Usage:
    python scripts\\run_experiment.py
    python scripts\\run_experiment.py --training 2000 --test 500 --episodes 20000
    python scripts\\run_experiment.py --label "wide-state test" --seed 43
"""

import argparse
import json
import sys
from pathlib import Path

# Allow running as a script without installing.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from aegis.experiment.persistance import save_experiment
from aegis.experiment.runner import run_experiment


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--training", type=int, default=1000)
    parser.add_argument("--test", type=int, default=250)
    parser.add_argument("--episodes", type=int, default=5000)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--label", type=str, default=None)
    parser.add_argument("--no-save", action="store_true")
    args = parser.parse_args()

    print(f"Running experiment: training={args.training} test={args.test} "
          f"episodes={args.episodes} seed={args.seed}")
    result = run_experiment(
        training_count=args.training,
        test_count=args.test,
        episodes=args.episodes,
        seed=args.seed,
    )

    print()
    print(f"Improvement vs best baseline: "
          f"{result['improvement_vs_best_baseline_pct']}% "
          f"(baseline = {result['best_baseline']})")
    print()
    print("Summary:")
    for row in result["summary"]:
        print(f"  {row['policy']:30s} mean_cost={row['mean_cost']:.4f} "
              f"residual_risk={row['mean_residual_risk']:.2f} "
              f"availability={row['mean_service_availability']:.2f}")
    print()
    print("Learned policy:")
    for state, action in result["learned_policy"].items():
        print(f"  {state:40s} -> {action}")

    if not args.no_save:
        meta = save_experiment(result, label=args.label)
        print()
        print(f"Saved: {meta['path']}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())