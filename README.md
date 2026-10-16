# AEGIS-D

**Adaptive Experimental Graph Intelligence for Security — D**

A cloud security research prototype that investigates a single question:

> Can an agent learn to select incident-response strategies that reduce security risk while minimising disruption to legitimate services — and can it outperform fixed response rules on incidents it has not seen?

AEGIS-D is a local, simulated research platform. It does not connect to any cloud provider, does not execute containment actions, and does not establish real-world response effectiveness.

---

## Result

Across 20 seeds, a tabular Q-learner improved on the best fixed response baseline by **8.94 % ± 1.44 %** on held-out scenarios, with positive improvement in every run.

The improvement is **regime-dependent**: when availability loss is weighted at or above risk reduction, the trivially optimal action (revoke privilege) matches the learned policy and no improvement remains. This defines an operating window in which adaptive response adds value — and, more usefully, when it does not.

Full methodology, weight sweeps, and a boundary characterisation are in [`RESULTS.md`](RESULTS.md).

---

## Architecture
events
|
v
+-----------------------------+
| Sentinel | rule-based detection
+-----------------------------+
|
v alerts
+-----------------------------+
| Chronicle | correlation into incidents
+-----------------------------+
|
v incidents
+-----------------------------+
| AttackGraph | identities / roles / services / resources
+-----------------------------+
|
v
+-----------------------------+
| Bridge (incident to | derives scenario features from
| scenario) | detection output
+-----------------------------+
|
v scenarios
+-----------------------------+
| Counterfactual Engine | simulated outcome model
+-----------------------------+
|
+-------------+-------------+
v v
Fixed baselines Adaptive Decision Engine
(three rules) (tabular Q-learner)
| |
+-------------+-------------+
v
+-----------------------------+
| Held-out evaluation | same test scenarios, all policies
+-----------------------------+

text

Every layer is implemented, tested, and integrated. The dashboard exposes the whole pipeline through a FastAPI backend.

---

## What is real and what is simulated

| Component | Status |
|---|---|
| Event generation | Synthetic, CloudTrail-flavoured |
| Detection rules | Deterministic, with MITRE technique mapping |
| Incident correlation | Real logic on synthetic data |
| Attack graph | Assumed relationships, not verified IAM |
| Response outcome model | Documented assumptions, not measurements |
| RL agent | Tabular Q-learning, 9 states, 3 actions, one-step |
| Evaluation | Real held-out protocol, simulated outcomes |
| Cloud integration | **None** — the safe research direction is simulation first |

Every assumption is documented in the code and in `RESULTS.md`. Nothing here has been validated against real incident data.

---

## Quick start

```powershell
# Clone and set up
git clone https://github.com/Naivete-1/AEGIS-D.git
cd AEGIS-D
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -e ".[dev]"

# Run the test suite (155 tests)
python -m pytest -v

# Run one full held-out experiment and save the result
python scripts\run_experiment.py

# Seed sweep and weight sweep
python scripts\analyse.py

# Boundary characterisation
python scripts\boundary_sweep.py

# Start the API and dashboard
python -m uvicorn aegis.api.main:app --reload
Then open http://127.0.0.1:8000/.

Dashboard
The dashboard has five views:

Overview — pipeline KPIs, attack-type distribution, training cost curve

Attack graph — interactive network of identities, roles, services, resources

Investigation — incidents with event timelines and MITRE technique tags

Response policy — learned policy vs. three fixed baselines on held-out data

Saved runs — history of every experiment, with configuration and results

Repository layout
text
AEGIS-D/
├── src/aegis/
│   ├── events/           Synthetic security events + schema
│   ├── sentinel/         Rule-based detection
│   ├── chronicle/        Incident correlation and incident-to-scenario bridge
│   ├── attackgraph/      NetworkX graph of assumed access relationships
│   ├── simulator/        Response outcome model
│   ├── agents/           Tabular Q-learner and baselines
│   ├── experiment/       Runner, persistence, robustness analysis
│   ├── scenarios/        Synthetic scenario generator
│   └── api/              FastAPI application
├── frontend/             Dashboard (HTML / CSS / JS)
├── scripts/              CLI entry points
├── tests/                155 pytest tests
├── results/              Experiment outputs (gitignored)
└── RESULTS.md            Full methodology and results
Technology
Component	Technology
Backend	Python 3.12, FastAPI, Uvicorn
Detection	Deterministic rules (ML anomaly detection planned)
Graph analysis	NetworkX
Agent	Tabular Q-learning (Gymnasium-compatible env planned)
Frontend	HTML, CSS, vanilla JavaScript, vis-network, Chart.js
Testing	pytest
Persistence	JSON files (SQLite planned)
Limitations
This is a research prototype, not a production security platform.

Simulated outcomes. Response effects are documented assumptions.

Hidden features. Attack type, detection confidence, and compromise scope influence outcomes but are not visible to the learning agent.

One-step decisions. No sequential state transitions; the discount factor is 0.

Uncalibrated weights. Cost weights and modulation factors are not justified against real incident data.

No cloud integration. The system never touches real infrastructure.

The central research contribution is the evidence produced by the held-out evaluation, not the number of technologies involved.

License
Not yet chosen. Until a license is added, all rights reserved.

text

---

## After you commit it

Refresh the repo page — the README will render as the front page.

Two things to check:
1. The architecture diagram renders as plain text (correct — it's in a code block, not a Mermaid diagram).
2. The clone URL in the Quick start says `github.com/Naivete-1/AEGIS-D.git` — which won't work until you rename the repo. Either rename the repo to `AEGIS-D` (recommended, GitHub → Settings → General → Repository name), or edit that line to match your current repo name.

Once it's live, say the word and we start the cloud-event refactor.
