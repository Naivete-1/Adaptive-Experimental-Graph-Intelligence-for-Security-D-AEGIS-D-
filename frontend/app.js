// AEGIS-D dashboard logic.

const KIND_COLOR = {
  identity: "#a78bfa",
  role: "#60a5fa",
  service: "#f472b6",
  resource: "#34d399",
};

const SENSITIVITY_BORDER = {
  low: "#34d399",
  medium: "#fbbf24",
  high: "#f87171",
};

// ─── Generic helpers ──────────────────────────────────────
async function getJSON(path) {
  const r = await fetch(path);
  if (!r.ok) throw new Error(await r.text());
  return r.json();
}

async function postJSON(path, body) {
  const r = await fetch(path, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  if (!r.ok) {
    const text = await r.text();
    let detail = text;
    try { detail = JSON.parse(text).detail || text; } catch {}
    throw new Error(detail);
  }
  return r.json();
}

function el(html) {
  const t = document.createElement("template");
  t.innerHTML = html.trim();
  return t.content.firstElementChild;
}

function badge(kind, value) {
  return `<span class="badge ${kind}">${value}</span>`;
}

// ─── State ────────────────────────────────────────────────
let currentIncidents = [];
let currentEventsById = {};
let attackTypeChart = null;
let trainingChart = null;
let policiesChart = null;

// ─── Navigation ───────────────────────────────────────────
const VIEW_TITLES = {
  overview: "Overview",
  graph: "Attack graph",
  investigation: "Incident investigation",
  experiment: "Response policy",
  runs: "Saved runs",
};

function switchView(name) {
  document.querySelectorAll(".nav-item").forEach((b) => {
    b.classList.toggle("active", b.dataset.view === name);
  });
  document.querySelectorAll(".view").forEach((v) => {
    v.classList.toggle("active", v.dataset.view === name);
  });
  document.getElementById("view-title").textContent = VIEW_TITLES[name] || name;
}

document.querySelectorAll(".nav-item").forEach((btn) => {
  btn.addEventListener("click", () => switchView(btn.dataset.view));
});

// ─── Attack graph rendering ───────────────────────────────
async function renderGraph() {
  const container = document.getElementById("graph-viz");
  if (!container) return;

  let data;
  try {
    data = await getJSON("/graph/data");
  } catch (e) {
    container.innerHTML = `<div class="error" style="margin:16px">${e.message}</div>`;
    return;
  }

  const nodes = new vis.DataSet(
    data.nodes.map((n) => ({
      id: n.id,
      label: n.label,
      shape: "box",
      color: {
        background: KIND_COLOR[n.kind] || "#6d7896",
        border: n.sensitivity
          ? SENSITIVITY_BORDER[n.sensitivity]
          : "transparent",
        highlight: { background: "#5ea9ff", border: "#0a0d14" },
      },
      font: { color: "#0a0d14", size: 13, face: "system-ui", bold: true },
      borderWidth: 3,
      borderWidthSelected: 4,
      margin: { top: 10, bottom: 10, left: 16, right: 16 },
      shadow: {
        enabled: true,
        color: "rgba(0,0,0,0.3)",
        size: 6,
        x: 0,
        y: 2,
      },
    }))
  );

  const edges = new vis.DataSet(
    data.edges.map((e) => ({
      from: e.from,
      to: e.to,
      arrows: { to: { enabled: true, scaleFactor: 0.7 } },
      label: e.relation,
      font: {
        color: "#a5b0c7",
        size: 11,
        face: "system-ui",
        strokeWidth: 5,
        strokeColor: "#0f1320",
      },
      color: { color: "#3a4764", highlight: "#5ea9ff" },
      width: 1.5,
      smooth: { type: "cubicBezier", roundness: 0.4 },
    }))
  );

  new vis.Network(
    container,
    { nodes, edges },
    {
      layout: {
        hierarchical: {
          direction: "LR",
          sortMethod: "directed",
          levelSeparation: 200,
          nodeSpacing: 140,
        },
      },
      physics: { enabled: false },
      interaction: { hover: true, dragNodes: true, zoomView: true },
    }
  );
}

async function renderGraphPaths() {
  const out = document.getElementById("graph-paths");
  const identity = document.getElementById("g-id").value.trim();
  if (!identity) return;
  out.innerHTML = `<div class="muted">Tracing…</div>`;

  try {
    const d = await getJSON(
      `/graph/paths?identity=${encodeURIComponent(identity)}`
    );
    if (!d.paths.length) {
      out.innerHTML = `<div class="empty">No paths from this identity.</div>`;
      return;
    }
    out.innerHTML =
      `<div class="muted" style="margin-bottom:12px">${d.paths.length} path(s) found · ${d.reachable_resources.length} reachable resource(s)</div>` +
      d.paths
        .map((p) => {
          const chain = p.path
            .map((n) => {
              const short = n.split(":").slice(-1)[0];
              return `<b>${short}</b>`;
            })
            .join('<span class="arrow">→</span>');
          return `
            <div class="path-item">
              <div class="path-meta">
                ${p.length} hops · <span class="risk-${p.risk}">risk ${p.risk}</span>
              </div>
              <div class="path-chain">${chain}</div>
            </div>`;
        })
        .join("");
  } catch (e) {
    out.innerHTML = `<div class="error">${e.message}</div>`;
  }
}

// ─── Detection pipeline ───────────────────────────────────
async function runPipeline() {
  const buttons = [
    document.getElementById("hero-run-pipeline"),
  ].filter(Boolean);
  buttons.forEach((b) => (b.disabled = true));

  try {
    const body = {
      event_count: 100,
      seed: 42,
      inject: ["brute_force", "privilege_escalation", "large_download"],
    };
    const d = await postJSON("/pipeline/run", body);

    // Overview metrics
    document.getElementById("m-events").textContent = d.event_count;
    document.getElementById("m-events-sub").textContent = "simulated security events";
    document.getElementById("m-alerts").textContent = d.alert_count;
    document.getElementById("m-alerts-sub").textContent = "rule-based detections";
    document.getElementById("m-incidents").textContent = d.incident_count;
    document.getElementById("m-incidents-sub").textContent = "correlated incidents";

    // Attack type distribution chart
    renderAttackTypeChart(d.scenarios);

    // Store incidents and events for the investigation view
    currentIncidents = d.incidents;
    currentEventsById = {};
    // The pipeline response doesn't ship raw events for each incident, but
    // the incident records contain the event_ids. We rebuild what we can
    // from the scenarios for display purposes.
    renderIncidentList(d.incidents);
    switchView("investigation");

  } catch (e) {
    alert("Pipeline failed: " + e.message);
  } finally {
    buttons.forEach((b) => (b.disabled = false));
  }
}

function renderAttackTypeChart(scenarios) {
  const counts = {};
  scenarios.forEach((s) => {
    const key = s.attack_type.replace(/_/g, " ");
    counts[key] = (counts[key] || 0) + 1;
  });

  const labels = Object.keys(counts);
  const values = labels.map((k) => counts[k]);

  const ctx = document.getElementById("chart-attack-types");
  if (!ctx) return;

  if (attackTypeChart) attackTypeChart.destroy();

  attackTypeChart = new Chart(ctx, {
    type: "doughnut",
    data: {
      labels,
      datasets: [
        {
          data: values,
          backgroundColor: ["#5ea9ff", "#a78bfa", "#f472b6", "#34d399"],
          borderColor: "#121826",
          borderWidth: 3,
        },
      ],
    },
    options: {
      maintainAspectRatio: false,
      cutout: "65%",
      plugins: {
        legend: {
          position: "right",
          labels: {
            color: "#a5b0c7",
            font: { size: 12 },
            padding: 12,
            boxWidth: 12,
            boxHeight: 12,
          },
        },
      },
    },
  });

  const hint = document.getElementById("dist-hint");
  if (hint) hint.textContent = `${scenarios.length} scenarios`;
}

// ─── Incidents ────────────────────────────────────────────
function renderIncidentList(incidents) {
  const list = document.getElementById("incident-list");
  const hint = document.getElementById("inc-hint");
  if (!list) return;

  if (!incidents || !incidents.length) {
    list.innerHTML = `<div class="empty">No incidents detected.</div>`;
    if (hint) hint.textContent = "no data";
    return;
  }

  if (hint) hint.textContent = `${incidents.length} incident(s)`;

  list.innerHTML = incidents
    .map(
      (inc, i) => `
      <div class="incident-item" data-index="${i}">
        <div class="inc-id">${inc.incident_id}</div>
        <div class="inc-user">${inc.user}</div>
        <div>${badge(inc.severity, inc.severity)}</div>
        <div class="inc-rules">
          ${inc.rule_names.map((r) => badge("service", r)).join("")}
        </div>
      </div>`
    )
    .join("");

  list.querySelectorAll(".incident-item").forEach((item) => {
    item.addEventListener("click", () => {
      list.querySelectorAll(".incident-item").forEach((i) =>
        i.classList.remove("selected")
      );
      item.classList.add("selected");
      showIncidentDetail(incidents[+item.dataset.index]);
    });
  });

  // Auto-select the first incident
  const first = list.querySelector(".incident-item");
  if (first) {
    first.classList.add("selected");
    showIncidentDetail(incidents[0]);
  }
}

function showIncidentDetail(inc) {
  const detail = document.getElementById("incident-detail");
  const hint = document.getElementById("inc-detail-hint");
  if (!detail) return;

  if (hint) hint.textContent = inc.incident_id;

  // The incident record from /pipeline/run strips the raw events, so we
  // synthesise a timeline from what we know: alert rules and their event
  // ids, plus the first/last seen timestamps.
  const events = inc.events || [];
  const timeline =
    events.length > 0
      ? events
          .slice()
          .sort((a, b) => a.timestamp.localeCompare(b.timestamp))
          .map((e) => timelineRow(e))
          .join("")
      : `<div class="empty">Event details unavailable for this view.<br>Re-run the pipeline and select an incident to populate the timeline.</div>`;

  detail.innerHTML = `
    <div style="margin-bottom:16px">
      <div style="font-size:12px;color:var(--muted);margin-bottom:4px">${inc.incident_id}</div>
      <div style="font-size:16px;font-weight:600;margin-bottom:8px">${inc.user}</div>
      <div style="display:flex;gap:6px;flex-wrap:wrap">
        ${badge(inc.severity, inc.severity)}
        ${inc.rule_names.map((r) => badge("service", r)).join("")}
        ${badge("role", "confidence " + inc.confidence)}
      </div>
    </div>
    <div style="font-size:12px;color:var(--muted);margin-bottom:14px">
      ${inc.summary}
    </div>
    <div class="timeline">${timeline}</div>
  `;
}

function timelineRow(event) {
  const kind = event.event_type || "unknown";
  let head = "";
  let desc = "";
  let mitre = "";

  if (kind === "login_attempt") {
    head = event.success ? "Successful login" : "Failed login attempt";
    desc = `${event.user} from ${event.source_ip}`;
    if (!event.success) mitre = "T1110";
  } else if (kind === "role_assignment") {
    head = "Privileged role assigned";
    desc = `role '${event.role}' assigned to ${event.user}`;
    mitre = "T1078";
  } else if (kind === "data_download") {
    head = `Data download (${event.records} records)`;
    desc = `${event.user} → ${event.resource || "unknown resource"}`;
    mitre = "T1530";
  } else {
    head = kind;
    desc = JSON.stringify(event);
  }

  return `
    <div class="timeline-event kind-${kind}">
      <div class="event-time">${event.timestamp}</div>
      <div class="event-head">
        ${head}${mitre ? `<span class="event-mitre">${mitre}</span>` : ""}
      </div>
      <div class="event-desc">${desc}</div>
    </div>
  `;
}

// ─── Experiment ───────────────────────────────────────────
async function runExperiment() {
  const buttons = [
    document.getElementById("hero-run-experiment"),
  ].filter(Boolean);
  buttons.forEach((b) => (b.disabled = true));

  try {
    const body = {
      training_count: 1000,
      test_count: 250,
      episodes: 5000,
      seed: 42,
    };
    const d = await postJSON("/experiment/run", body);

    const pct = d.improvement_vs_best_baseline_pct;

    // Overview KPI
    document.getElementById("m-improvement").textContent = pct.toFixed(2) + "%";
    document.getElementById("m-improvement").classList.add(pct >= 0 ? "good" : "bad");
    document.getElementById("m-improvement-sub").textContent =
      "vs " + d.best_baseline.replace(/_/g, " ");

    // Experiment view metrics
    document.getElementById("x-improvement").textContent = pct.toFixed(2) + "%";
    document.getElementById("x-improvement-sub").textContent =
      "vs " + d.best_baseline.replace(/_/g, " ");
    document.getElementById("x-baseline").textContent =
      d.best_baseline.replace(/_/g, " ");
    document.getElementById("x-test-count").textContent = d.config.test_count;
    document.getElementById("x-train-count").textContent =
      `${d.config.training_count} training scenarios`;
    document.getElementById("x-episodes").textContent = d.config.episodes;

    renderPoliciesChart(d.summary);
    renderPolicyTable(d.learned_policy);
    renderComparisonTable(d.summary);

    // Training history chart on Overview
    if (d.training_history && d.training_history.length) {
      renderTrainingChart(d.training_history);
    }

    switchView("experiment");

  } catch (e) {
    alert("Experiment failed: " + e.message);
  } finally {
    buttons.forEach((b) => (b.disabled = false));
  }
}

function renderPoliciesChart(summary) {
  const ctx = document.getElementById("chart-policies");
  if (!ctx) return;

  if (policiesChart) policiesChart.destroy();

  policiesChart = new Chart(ctx, {
    type: "bar",
    data: {
      labels: summary.map((r) => r.policy.replace(/_/g, " ")),
      datasets: [
        {
          label: "Mean cost",
          data: summary.map((r) => r.mean_cost),
          backgroundColor: summary.map((r) =>
            r.policy === "learned_policy" ? "#5ea9ff" : "#3a4764"
          ),
          borderRadius: 4,
          borderSkipped: false,
        },
      ],
    },
    options: {
      indexAxis: "y",
      maintainAspectRatio: false,
      plugins: {
        legend: { display: false },
        tooltip: {
          callbacks: {
            label: (c) => `Mean cost: ${c.parsed.x.toFixed(3)}`,
          },
        },
      },
      scales: {
        x: {
          grid: { color: "#1f2942" },
          ticks: { color: "#a5b0c7", font: { size: 11 } },
          title: {
            display: true,
            text: "Mean cost (lower is better)",
            color: "#a5b0c7",
            font: { size: 11 },
          },
        },
        y: {
          grid: { display: false },
          ticks: { color: "#e8edf7", font: { size: 11 } },
        },
      },
    },
  });
}

function renderTrainingChart(history) {
  const ctx = document.getElementById("chart-training");
  if (!ctx) return;

  if (trainingChart) trainingChart.destroy();

  trainingChart = new Chart(ctx, {
    type: "line",
    data: {
      labels: history.map((_, i) => i),
      datasets: [
        {
          label: "Mean cost",
          data: history,
          borderColor: "#5ea9ff",
          backgroundColor: "rgba(94,169,255,0.08)",
          fill: true,
          tension: 0.35,
          pointRadius: 0,
          borderWidth: 2,
        },
      ],
    },
    options: {
      maintainAspectRatio: false,
      plugins: {
        legend: { display: false },
        tooltip: {
          callbacks: {
            label: (c) => `Cost: ${c.parsed.y.toFixed(3)}`,
          },
        },
      },
      scales: {
        x: {
          grid: { color: "#1f2942" },
          ticks: { color: "#6d7896", font: { size: 10 }, maxTicksLimit: 8 },
          title: {
            display: true,
            text: "Training progress (sampled)",
            color: "#6d7896",
            font: { size: 11 },
          },
        },
        y: {
          grid: { color: "#1f2942" },
          ticks: { color: "#a5b0c7", font: { size: 11 } },
        },
      },
    },
  });
}

function renderPolicyTable(policy) {
  const out = document.getElementById("policy-table");
  if (!out) return;

  const rows = Object.entries(policy)
    .map(
      ([state, action]) => `
      <tr>
        <td class="mono">${state.replace(/_/g, " ")}</td>
        <td class="mono">${action}</td>
      </tr>`
    )
    .join("");

  out.innerHTML = `
    <table>
      <thead><tr><th>State</th><th>Action</th></tr></thead>
      <tbody>${rows}</tbody>
    </table>
  `;
}

function renderComparisonTable(summary) {
  const out = document.getElementById("policy-comparison");
  if (!out) return;

  out.innerHTML = `
    <table>
      <thead>
        <tr>
          <th>Policy</th>
          <th>Mean cost</th>
          <th>Residual risk</th>
          <th>Availability</th>
          <th>Recovery (min)</th>
        </tr>
      </thead>
      <tbody>
        ${summary
          .map(
            (r) => `
          <tr>
            <td class="mono">${r.policy.replace(/_/g, " ")}</td>
            <td>${r.mean_cost.toFixed(3)}</td>
            <td>${r.mean_residual_risk.toFixed(2)}</td>
            <td>${r.mean_service_availability.toFixed(2)}</td>
            <td>${r.mean_recovery_minutes.toFixed(2)}</td>
          </tr>`
          )
          .join("")}
      </tbody>
    </table>
  `;
}

// ─── Saved runs ───────────────────────────────────────────
async function loadRuns() {
  const out = document.getElementById("runs-table");
  if (!out) return;
  out.innerHTML = `<div class="muted">Loading…</div>`;

  try {
    const d = await getJSON("/experiment/runs");
    if (!d.runs.length) {
      out.innerHTML = `<div class="empty">No saved runs yet. Run an experiment first.</div>`;
      return;
    }

    out.innerHTML = `
      <table>
        <thead>
          <tr>
            <th>Run ID</th>
            <th>Seed</th>
            <th>Improvement</th>
            <th>Learned cost</th>
            <th>Saved at</th>
          </tr>
        </thead>
        <tbody>
          ${d.runs
            .slice()
            .reverse()
            .map(
              (r) => `
            <tr>
              <td class="mono">${r.run_id}</td>
              <td>${r.seed}</td>
              <td>${
                r.improvement_vs_best_baseline_pct != null
                  ? r.improvement_vs_best_baseline_pct.toFixed(2) + "%"
                  : "—"
              }</td>
              <td>${
                r.learned_mean_cost != null
                  ? r.learned_mean_cost.toFixed(3)
                  : "—"
              }</td>
              <td class="muted">${(r.saved_at || "").slice(0, 19).replace("T", " ")}</td>
            </tr>`
            )
            .join("")}
        </tbody>
      </table>
    `;
  } catch (e) {
    out.innerHTML = `<div class="error">${e.message}</div>`;
  }
}

// ─── Wiring ───────────────────────────────────────────────
document.getElementById("hero-run-pipeline")?.addEventListener("click", runPipeline);
document.getElementById("hero-run-experiment")?.addEventListener("click", runExperiment);
document.getElementById("refresh-runs")?.addEventListener("click", loadRuns);
document.getElementById("trace-btn")?.addEventListener("click", renderGraphPaths);

// Init
renderGraph();
renderGraphPaths();