# AEGIS-D — Experimental Results

**Status:** work in progress. Frozen as of the run recorded below.
**Environment:** local, CPU only, Python 3.12.
**Code version:** see git tag (to be added).

---

## 1. Research question

Can an agent learn to select incident-response strategies that reduce
security risk while minimising disruption to legitimate services, and can
it outperform fixed response rules on incidents it has not seen?

---

## 2. Method

### 2.1 Simulator

Incidents are represented as scenarios with five features:

| Feature | Values |
|---|---|
| severity | low, medium, high |
| criticality | low, medium, high |
| attack_type | brute_force, privilege_escalation, data_exfiltration |
| detection_confidence | low, medium, high |
| compromise_scope | single_identity, multiple_identities, service_affected |

Three response strategies are available:

| Strategy | Base risk reduction | Base availability loss | Base recovery (min) |
|---|---|---|---|
| disable_identity | 85 | 35 | 60 |
| isolate_service | 70 | 20 | 35 |
| revoke_privilege | 55 | 5 | 15 |

Outcome for each (strategy, scenario) pair is computed by applying four
documented modulations on the base table:

- attack type scales risk reduction per strategy
- detection confidence scales risk reduction uniformly
- compromise scope scales risk reduction per strategy
- criticality scales availability loss and recovery time

Response cost:
C = w_rr · residual_risk + w_av · availability_loss + w_rc · recovery_score

text

Default weights: `w_rr = 0.6, w_av = 0.3, w_rc = 0.1`.

All outcome parameters are **assumptions**, not measurements.

### 2.2 Agent

Tabular Q-learning, one-step, discount factor 0.0. State is
`(severity, criticality)` — 9 states. Actions are the three response
strategies. Reward is negative cost. Epsilon-greedy with ε = 0.2,
learning rate = 0.1.

The agent does **not** see attack type, detection confidence, or
compromise scope. Those features affect the outcome but are hidden from
the agent. This is a deliberate limitation for v0.1.

### 2.3 Baselines

Three fixed policies are evaluated on the same held-out data:

- always disable identity
- always isolate service
- always revoke privilege

### 2.4 Protocol

1. Generate 1,000 training scenarios (seed = 42).
2. Generate 250 held-out test scenarios (seed = 43).
3. Train the agent on the training set for 5,000 episodes.
4. Evaluate the learned policy and each baseline on the same test set.
5. Improvement = (best_baseline_cost − learned_cost) / best_baseline_cost × 100.

---

## 3. Results

### 3.1 Main result (seed sweep, 20 seeds)

Each seed produces a fresh training set, fresh test set, and a fresh
trained agent. All 20 runs used `training_count=1000`, `test_count=250`,
`episodes=5000`, default weights.

| Statistic | Value |
|---|---|
| Mean improvement over best baseline | **8.94 %** |
| Standard deviation | 1.44 % |
| Minimum | 6.71 % |
| Maximum | 11.05 % |
| Fraction of runs with positive improvement | **20/20 (100 %)** |

The learned policy improved on the best fixed baseline in every seed.
### 3.2 Weight sensitivity and collapse boundary (fixed seed = 42)

The improvement figure depends on the cost weights. The sweep varies
availability-loss weight while holding recovery weight (0.1) fixed and
letting risk weight absorb the remainder:

| w_risk | w_avail | Improvement | Best baseline | Learned policy |
|---|---|---|---|---|
| 0.80 | 0.10 | 0.42 % | always_isolate_service | adaptive |
| 0.75 | 0.15 | 4.67 % | always_isolate_service | adaptive |
| 0.70 | 0.20 | 2.60 % | always_isolate_service | adaptive |
| 0.65 | 0.25 | 7.37 % | always_isolate_service | adaptive |
| 0.60 | 0.30 | 8.69 % | always_isolate_service | adaptive |
| 0.55 | 0.35 | **9.98 %** | always_isolate_service | adaptive |
| 0.50 | 0.40 | 3.92 % | always_revoke_privilege | adaptive |
| 0.45 | 0.45 | 2.77 % | always_revoke_privilege | adaptive |
| 0.40 | 0.50 | 0.00 % | always_revoke_privilege | revoke_privilege |

**Observation.** Improvement is **non-monotonic** in availability weight.
It peaks around `w_avail = 0.35` at 9.98 %, then collapses. The best
fixed baseline flips from `isolate_service` to `revoke_privilege` at
`w_avail ≈ 0.40`. At `w_avail = 0.50`, the learned policy becomes a
constant (`revoke_privilege` in every state) and improvement is exactly 0 %.

**Interpretation.** Adaptive response adds value only in a specific
operating regime — where risk reduction and service availability are
*competitive* concerns. When either dominates the cost function:

- **Risk-dominant** (`w_avail ≤ 0.15`): a single aggressive action
  dominates, and the agent has little to differentiate.
- **Availability-dominant** (`w_avail ≥ 0.50`): the trivially optimal
  action is the least disruptive one, and a fixed rule matches it.
- **Balanced** (`w_avail ∈ [0.25, 0.35]`): the learned policy finds a
  graduated response that neither fixed rule captures.

This is a claim about response-strategy design, not just a hyperparameter
sensitivity. It identifies *when* adaptive response is worth its
complexity — and, more usefully, when it isn't.

*(Note: the non-monotonic wiggles in the range `w_avail ∈ [0.10, 0.25]`
are single-seed and may reflect sampling noise rather than structure. A
multi-seed boundary sweep would settle this. See §4.)*

Default weights: `w_rr = 0.6, w_av = 0.3, w_rc = 0.1`.

All outcome parameters are **assumptions**, not measurements.

### 3.3 Learned policy at default weights

| State | Action |
|---|---|
| low severity, any criticality | revoke_privilege |
| medium severity, any criticality | isolate_service |
| high severity, low/medium criticality | isolate_service |
| high severity, high criticality | (record from run) |

The policy graduates response intensity by severity — mild for low-
severity incidents, mid-range for higher-severity ones — without having
been told to do so.

---

## 4. Limitations

1. **Simulated outcomes.** Response effects are documented assumptions.
   Nothing in this document establishes real-world effectiveness.
2. **Hidden features.** Attack type, detection confidence, and compromise
   scope influence outcomes but are not visible to the agent. This bounds
   what the learned policy can be.
3. **Single environment.** No sequential state transitions; the decision
   is one-step with discount factor 0.
4. **Weight dependence.** The reported improvement is regime-dependent,
   as §3.2 shows.
5. **No calibration.** Cost weights and modulation factors have not been
   justified against real incident-response data.
6. **Single-seed boundary sweep.** §3.2 uses one seed per weight.
   The non-monotonic features in the low-availability range could be
   sampling variance rather than structure. Multi-seed replication at
   each weight is required before the peak location is treated as
   precise.

---

## 5. Reproducibility

All results can be reproduced from a clean checkout:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -e .
pip install pytest

python -m pytest -v                         # 67 tests
python scripts\run_experiment.py            # one run, saved to results/
python scripts\analyse.py                   # seed + weight sweeps
python scripts\boundary_sweep.py            # collapse-point characterisation
