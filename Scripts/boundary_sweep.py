"""
Boundary characterisation.

Sweep availability_loss weight finely while holding residual_risk and
recovery_time fixed. For each configuration, record:
  - the learned policy
  - the improvement over the best fixed baseline
  - which baseline was best

The goal is to locate the point at which the learned policy stops adding
value, and confirm that the collapse coincides with the learned policy
becoming identical to a fixed baseline.
"""

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from aegis.experiment.runner import run_experiment


def _policy_is_constant(policy: dict) -> str | None:
    """If the learned policy always picks one action, return it; else None."""
    actions = set(policy.values())
    return next(iter(actions)) if len(actions) == 1 else None


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--training", type=int, default=1000)
    parser.add_argument("--test", type=int, default=250)
    parser.add_argument("--episodes", type=int, default=5000)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--start", type=float, default=0.10,
                        help="smallest availability weight")
    parser.add_argument("--end", type=float, default=0.50,
                        help="largest availability weight")
    parser.add_argument("--step", type=float, default=0.05,
                        help="grid step for availability weight")
    parser.add_argument("--out", type=str, default="results/boundary.json")
    args = parser.parse_args()

    # Build grid: residual + availability + recovery = 1.0, recovery fixed at 0.1
    grid = []
    w = args.start
    while w <= args.end + 1e-9:
        residual = round(1.0 - w - 0.1, 4)
        if residual < 0:
            break
        grid.append({
            "residual_risk": round(residual, 4),
            "availability_loss": round(w, 4),
            "recovery_time": 0.1,
        })
        w = round(w + args.step, 4)

    print(f"Sweeping {len(grid)} configurations "
          f"(seed={args.seed}, episodes={args.episodes})")
    print()
    print(f"{'w_avail':>8} {'w_risk':>8} | "
          f"{'improve%':>9} {'best_baseline':>26} {'learned_policy':>20}")
    print("-" * 82)

    per_config = []
    for weights in grid:
        result = run_experiment(
            training_count=args.training,
            test_count=args.test,
            episodes=args.episodes,
            seed=args.seed,
            weights=weights,
        )
        improvement = result["improvement_vs_best_baseline_pct"]
        best_baseline = result["best_baseline"]
        constant = _policy_is_constant(result["learned_policy"])
        policy_desc = constant if constant else "adaptive"

        per_config.append({
            "weights": weights,
            "improvement_pct": improvement,
            "best_baseline": best_baseline,
            "learned_policy": result["learned_policy"],
            "learned_policy_is_constant": constant is not None,
            "learned_policy_constant_action": constant,
        })

        print(f"{weights['availability_loss']:>8.2f} "
              f"{weights['residual_risk']:>8.2f} | "
              f"{improvement:>9.4f} "
              f"{best_baseline:>26} "
              f"{policy_desc:>20}")

    # Find the collapse point: first config (from low availability weight)
    # where improvement is zero or the policy becomes constant.
    collapse = None
    for entry in per_config:
        if (entry["learned_policy_is_constant"]
                or entry["improvement_pct"] <= 1e-6):
            collapse = entry
            break

    print()
    if collapse:
        w = collapse["weights"]
        print(f"Collapse detected at availability_weight = "
              f"{w['availability_loss']:.2f}, "
              f"residual_risk = {w['residual_risk']:.2f}")
        print(f"  improvement: {collapse['improvement_pct']}%")
        print(f"  best baseline: {collapse['best_baseline']}")
        print(f"  learned policy: "
              f"{collapse['learned_policy_constant_action'] or 'adaptive but tied'}")
    else:
        print("No collapse detected in this range — improvement remained "
              "positive and the learned policy stayed adaptive throughout.")

    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps({
        "config": {
            "training_count": args.training,
            "test_count": args.test,
            "episodes": args.episodes,
            "seed": args.seed,
            "grid_start": args.start,
            "grid_end": args.end,
            "grid_step": args.step,
        },
        "per_config": per_config,
        "collapse": collapse,
    }, indent=2), encoding="utf-8")
    print()
    print(f"Saved: {out_path}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())