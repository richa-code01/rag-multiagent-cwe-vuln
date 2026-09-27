const state = { catalog: null, jobId: null, timer: null };

function panel(name) {
  document.querySelectorAll(".panel").forEach((node) => node.classList.add("hidden"));
  document.getElementById(name).classList.remove("hidden");
  document.querySelectorAll(".tabs button").forEach((button) => {
    button.classList.toggle("active", button.dataset.tab === name);
  });
}

document.querySelectorAll(".tabs button").forEach((button) => {
  button.addEventListener("click", () => panel(button.dataset.tab));
});

async function getJSON(url, options) {
  const response = await fetch(url, options);
  const payload = await response.json().catch(() => ({}));
  if (!response.ok) {
    const detail = payload.detail || response.statusText;
    throw new Error(typeof detail === "string" ? detail : JSON.stringify(detail));
  }
  return payload;
}

function metricLine(trial) {
  const pair = trial.pair_metrics;
  if (pair && pair.accuracy != null) {
    const ci = pair.bootstrap_95;
    const span = ci ? ` CI [${Number(ci.low ?? ci[0]).toFixed(3)}, ${Number(ci.high ?? ci[1]).toFixed(3)}]` : "";
    return `pair ${pair.correct}/${pair.n_pairs} = ${Number(pair.accuracy).toFixed(3)}${span}`;
  }
  const metrics = trial.metrics;
  if (metrics && metrics.f1 != null) {
    return `F1 ${Number(metrics.f1).toFixed(3)} n=${metrics.support ?? trial.n_units ?? "—"}`;
  }
  return trial.notes || "no score";
}

function renderCards(summary) {
  const root = document.getElementById("cards");
  const trials = (summary.thesis && summary.thesis.trials) || [];
  document.getElementById("retracted").textContent = summary.retracted_note || "";
  root.innerHTML = "";
  if (!trials.length) {
    root.textContent = "No thesis summary on disk.";
    return;
  }
  for (const trial of trials) {
    const button = document.createElement("button");
    button.type = "button";
    button.className = "card";
    const status = trial.status || "unknown";
    button.innerHTML = `<strong>${trial.trial_id}</strong><span class="status status-${status}">${status}</span><span>${metricLine(trial)}</span>`;
    button.addEventListener("click", () => showTrial(trial.trial_id));
    root.appendChild(button);
  }
}

async function showTrial(trialId) {
  const detail = document.getElementById("detail");
  detail.textContent = "Loading…";
  try {
    const trial = await getJSON(`/api/results/${encodeURIComponent(trialId)}`);
    const rows = (trial.unit_decisions || []).slice(0, 40);
    const table = rows.map((row) =>
      `<tr><td>${row.unit_id}</td><td>${row.decision}</td><td>${row.gold_label}</td><td>${row.predicted_cwe}</td><td>${row.cwe_tier || ""}</td><td>${row.validator_passed}</td></tr>`
    ).join("");
    detail.innerHTML = `${trial.trial_id} · ${trial.status}\n${trial.disclaimer || ""}\n\n${metricLine(trial)}\n\n<table><thead><tr><th>Unit</th><th>Decision</th><th>Gold</th><th>CWE</th><th>Tier</th><th>Validator</th></tr></thead><tbody>${table}</tbody></table>`;
  } catch (error) {
    detail.textContent = error.message;
  }
}

function formSpec(form) {
  const data = new FormData(form);
  return {
    kind: data.get("kind"),
    suite: data.get("suite"),
    ablation: data.get("ablation"),
    split: data.get("split"),
    offline: data.get("offline") === "on" || data.get("ablation") === "template",
    resume: data.get("resume") === "on",
    include_model_ablation: data.get("include_model_ablation") === "on",
    max_tokens: data.get("max_tokens") ? Number(data.get("max_tokens")) : null,
  };
}

function renderCommand() {
  const spec = formSpec(document.getElementById("run-form"));
  const parts = spec.kind === "pipeline"
    ? ["uv run cwe-vuln-pipeline", "--split", spec.split]
    : ["uv run cwe-vuln-eval", "--suite", spec.suite];
  if (spec.kind === "pipeline" && spec.offline) parts.push("--offline");
  if (spec.kind === "eval") {
    if (spec.offline) parts.push("--offline");
    else if (spec.ablation === "skip-llm") parts.push("--ablation", "skip-llm");
    if (spec.resume) parts.push("--resume");
    if (spec.max_tokens) parts.push("--max-tokens", String(spec.max_tokens));
    if (spec.include_model_ablation) parts.push("--include-model-ablation");
  }
  document.getElementById("command").textContent = parts.join(" ");
}

function fillCatalog(catalog) {
  state.catalog = catalog;
  const suite = document.getElementById("suite");
  suite.innerHTML = catalog.eval_suites.map((name) => `<option value="${name}">${name}</option>`).join("");
  const provider = document.getElementById("provider");
  provider.innerHTML = catalog.providers.map((item) =>
    `<option value="${item.name}">${item.name}${item.key_configured ? "" : " (no key)"}</option>`
  ).join("");
  const experiments = document.getElementById("experiments");
  experiments.innerHTML = catalog.experiments.map((item) =>
    `<li><strong>${item.title}</strong> — <code>${item.command}</code><br>${item.note}</li>`
  ).join("");
  provider.addEventListener("change", () => {
    const selected = catalog.providers.find((item) => item.name === provider.value);
    document.getElementById("model").innerHTML = (selected?.models || []).map((name) => `<option>${name}</option>`).join("");
    document.getElementById("key-state").textContent = selected?.key_configured ? "key configured" : "key missing";
  });
  provider.dispatchEvent(new Event("change"));
  document.getElementById("run-form").addEventListener("input", renderCommand);
  renderCommand();
}

async function pollJob() {
  if (!state.jobId) return;
  const job = await getJSON(`/api/jobs/${state.jobId}`);
  const log = (job.log || []).join("\n");
  document.getElementById("job-log").textContent = `${job.status} ${job.command || ""}\n${log}${job.error ? "\n" + job.error : ""}`;
  document.getElementById("cancel").disabled = job.status !== "running";
  if (job.status === "running") {
    state.timer = setTimeout(pollJob, 1500);
  } else {
    loadStatus();
  }
}

async function loadStatus() {
  const summary = await getJSON("/api/results");
  renderCards(summary);
}

async function loadSpotcheck() {
  const payload = await getJSON("/api/spotcheck");
  document.getElementById("spot-note").textContent = `${payload.status}: ${payload.notes || ""}`;
  const form = document.getElementById("spot-form");
  form.innerHTML = (payload.rows || []).map((row, index) => `
    <fieldset>
      <legend>${row.unit_id}</legend>
      <p>${row.decision} vs ${row.gold_label} · ${row.predicted_cwe} / ${row.gold_cwe}</p>
      <label>Explanation correct
        <select name="explanation_correct" data-index="${index}">
          <option value="">empty</option>
          <option value="true" ${row.explanation_correct === true ? "selected" : ""}>yes</option>
          <option value="false" ${row.explanation_correct === false ? "selected" : ""}>no</option>
        </select>
      </label>
      <label>Remediation useful
        <select name="remediation_useful" data-index="${index}">
          <option value="">empty</option>
          <option value="true" ${row.remediation_useful === true ? "selected" : ""}>yes</option>
          <option value="false" ${row.remediation_useful === false ? "selected" : ""}>no</option>
        </select>
      </label>
    </fieldset>
  `).join("") + `<button type="submit">Save labels</button>`;
  form.onsubmit = async (event) => {
    event.preventDefault();
    const rows = (payload.rows || []).map((row, index) => {
      const explanation = form.querySelector(`[name="explanation_correct"][data-index="${index}"]`).value;
      const remediation = form.querySelector(`[name="remediation_useful"][data-index="${index}"]`).value;
      return {
        unit_id: row.unit_id,
        explanation_correct: explanation === "" ? null : explanation === "true",
        remediation_useful: remediation === "" ? null : remediation === "true",
      };
    });
    const saved = await getJSON("/api/spotcheck", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ rows }),
    });
    document.getElementById("spot-note").textContent = `${saved.status}: ${saved.notes}`;
  };
}

document.getElementById("run-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const spec = formSpec(event.target);
  try {
    const job = await getJSON("/api/jobs", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(spec),
    });
    state.jobId = job.id;
    document.getElementById("cancel").disabled = false;
    pollJob();
  } catch (error) {
    document.getElementById("job-log").textContent = error.message;
  }
});

document.getElementById("cancel").addEventListener("click", async () => {
  if (!state.jobId) return;
  await getJSON(`/api/jobs/${state.jobId}/cancel`, { method: "POST" });
});

document.getElementById("inspect-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const data = new FormData(event.target);
  const out = document.getElementById("inspect-out");
  out.textContent = "Running…";
  try {
    const report = await getJSON("/api/inspect", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        unit_id: data.get("unit_id") || null,
        source: data.get("source") || null,
        offline: data.get("offline") === "on",
      }),
    });
    const reasoning = report.reasoning || {};
    const hits = (report.hits || []).map((hit) => `${hit.cwe_id} ${hit.name}`).join("\n");
    out.textContent = [
      `decision ${reasoning.decision} ${reasoning.cwe?.id || ""}`,
      `path ${report.path} reasoner ${report.reasoner}`,
      `validator ${report.validation?.passed}`,
      hits && `hits\n${hits}`,
      reasoning.explanation || "",
    ].filter(Boolean).join("\n\n");
  } catch (error) {
    out.textContent = error.message;
  }
});

document.getElementById("kb-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const q = new FormData(event.target).get("q");
  const payload = await getJSON(`/api/kb?q=${encodeURIComponent(q)}`);
  document.getElementById("kb-hits").innerHTML = `<ul>${payload.hits.map((hit) =>
    `<li><button type="button" data-cwe="${hit.id}">${hit.id}</button> ${hit.name} (${hit.score})</li>`
  ).join("")}</ul>`;
  document.querySelectorAll("[data-cwe]").forEach((button) => {
    button.addEventListener("click", async () => {
      const entry = await getJSON(`/api/kb/${button.dataset.cwe}`);
      document.getElementById("kb-hits").insertAdjacentHTML("beforeend", `<article><h3>${entry.id} ${entry.name}</h3><p>${entry.description}</p></article>`);
    });
  });
});

document.getElementById("retrieve-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const query = new FormData(event.target).get("query");
  const payload = await getJSON("/api/retrieve", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ query, k: 5 }),
  });
  document.getElementById("retrieve-hits").textContent = `${payload.embedder}\n` + payload.hits.map((hit) =>
    `${hit.cwe_id} ${hit.score.toFixed(3)} ${hit.name}`
  ).join("\n");
});

getJSON("/api/catalog").then(fillCatalog).catch((error) => {
  document.getElementById("command").textContent = error.message;
});
loadStatus().catch((error) => {
  document.getElementById("cards").textContent = error.message;
});
loadSpotcheck().catch((error) => {
  document.getElementById("spot-note").textContent = error.message;
});
