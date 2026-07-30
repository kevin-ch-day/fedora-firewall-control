"use strict";

import {
  activeState,
  display,
  freshnessLabel,
  operatorGuidance,
  postureSummary,
  recommendationRoute,
  titleCase,
} from "/assets/dashboard-model.js";

const byId = (id) => document.getElementById(id);
const text = (id, value) => { byId(id).textContent = value; };
const AUTO_REFRESH_MS = 30_000;
let refreshing = false;
let nextRefreshAt = 0;
let refreshTimer;
let countdownTimer;
let latestSnapshot;
let autoRefreshEnabled = true;
let feedbackTimer;

function setConnection(state, label) {
  const element = byId("connection-state");
  element.className = `connection ${state}`;
  element.lastElementChild.textContent = label;
}

function setTone(id, value, tone) {
  text(id, value);
  byId(id).className = `tone-${tone}`;
}

function showFeedback(message, isError = false) {
  clearTimeout(feedbackTimer);
  const feedback = byId("action-feedback");
  feedback.textContent = message;
  feedback.className = `action-feedback${isError ? " error" : ""}`;
  feedbackTimer = setTimeout(() => { feedback.textContent = ""; }, 4_000);
}

function renderGuidance(snapshot) {
  const list = byId("guidance-list");
  list.replaceChildren();
  for (const guidance of operatorGuidance(snapshot)) {
    const item = document.createElement("li");
    const label = document.createElement("b");
    const content = document.createElement("div");
    const title = document.createElement("strong");
    const detail = document.createElement("span");
    label.className = `guidance-kind ${guidance.kind}`;
    label.textContent = guidance.kind.toUpperCase();
    title.textContent = guidance.title;
    detail.textContent = guidance.detail;
    content.append(title, detail);
    if (guidance.command) {
      const command = document.createElement("code");
      command.textContent = guidance.command;
      content.append(command);
    }
    item.append(label, content);
    list.append(item);
  }
}

function render(snapshot, source) {
  const risk = snapshot.risk;
  const firewall = snapshot.firewall;
  const listeners = snapshot.listeners;
  const network = snapshot.network;

  text("posture-title", titleCase(risk.level));
  byId("posture-title").className = `tone-${risk.level}`;
  text("recommendation", snapshot.recommendation.summary);
  text("recommendation-severity", `SEVERITY ${titleCase(snapshot.recommendation.severity)}`);
  byId("recommendation-severity").className = `meta-chip severity-${snapshot.recommendation.severity}`;
  text("recommendation-category", `CATEGORY ${titleCase(snapshot.recommendation.category)}`);
  const recommendationDestination = recommendationRoute(snapshot.recommendation.destination);
  byId("recommendation-destination").href = recommendationDestination.href;
  text("recommendation-destination", `${recommendationDestination.label} →`);
  text("mode", titleCase(snapshot.assessment.mode));
  text("blockers", risk.blockers);
  text("reviews", risk.review_items);
  text("gaps", risk.coverage_gaps);
  const readiness = snapshot.assessment.defcon_readiness;
  setTone("readiness", titleCase(readiness), readiness === "ready" ? "ready" : readiness === "not_ready" ? "blocked" : "review_required");
  setTone("evidence-state", titleCase(snapshot.evidence.status), snapshot.evidence.status === "available" ? "ready" : snapshot.evidence.status === "partial" ? "review_required" : "blocked");
  setTone("freshness", freshnessLabel(snapshot), snapshot.stale ? "blocked" : "ready");

  text("firewall-active", activeState(firewall.active));
  text("firewall-zone", display(firewall.default_zone));
  text("binding-count", display(listeners.reachable_bindings, "—"));
  text("port-count", display(firewall.inbound_port_rules, "—"));
  text("overview-interface", display(network.physical_interface));
  text("overview-tunnel", display(network.tunnel_detection.tunnel_interface, "NONE"));
  text("overview-evidence", titleCase(snapshot.evidence.status));
  text("overview-gaps", risk.coverage_gaps);
  renderGuidance(snapshot);

  text("hostname", display(snapshot.hostname, "local host"));
  text("app-version", display(snapshot.application_version, "—"));
  text("snapshot-id", `#${snapshot.snapshot_id}`);
  text("snapshot-source", titleCase(source));
  const collected = new Date(snapshot.collected_at);
  text("collected-at", Number.isNaN(collected.valueOf()) ? snapshot.collected_at : collected.toLocaleString());
  byId("collected-at").dateTime = snapshot.collected_at;
  byId("error-banner").hidden = true;
  latestSnapshot = snapshot;
  byId("copy-summary").disabled = false;
  byId("export-snapshot").disabled = false;
  setConnection(snapshot.status === "available" ? "ready" : snapshot.status === "partial" ? "partial" : "error", titleCase(snapshot.status));
}

function updateCountdown() {
  if (!autoRefreshEnabled) {
    text("refresh-countdown", "PAUSED");
    return;
  }
  if (document.hidden) {
    text("refresh-countdown", "PAUSED");
    return;
  }
  const remainingSeconds = Math.max(0, Math.ceil((nextRefreshAt - Date.now()) / 1000));
  text("refresh-countdown", refreshing ? "COLLECTING" : `${remainingSeconds}s`);
}

function scheduleRefresh() {
  clearTimeout(refreshTimer);
  clearInterval(countdownTimer);
  nextRefreshAt = Date.now() + AUTO_REFRESH_MS;
  updateCountdown();
  if (!autoRefreshEnabled) return;
  countdownTimer = setInterval(updateCountdown, 1_000);
  if (!document.hidden) refreshTimer = setTimeout(() => void refresh(), AUTO_REFRESH_MS);
}

function toggleAutoRefresh() {
  autoRefreshEnabled = !autoRefreshEnabled;
  text("toggle-refresh", autoRefreshEnabled ? "Pause auto-refresh" : "Resume auto-refresh");
  if (autoRefreshEnabled) {
    showFeedback("Automatic collection resumed.");
    void refresh();
  } else {
    clearTimeout(refreshTimer);
    clearInterval(countdownTimer);
    updateCountdown();
    showFeedback("Automatic collection paused. Manual refresh remains available.");
  }
}

async function copySummary() {
  if (latestSnapshot === undefined) return;
  if (navigator.clipboard === undefined) {
    showFeedback("Clipboard access is unavailable in this browser.", true);
    return;
  }
  try {
    await navigator.clipboard.writeText(postureSummary(latestSnapshot));
    showFeedback("Posture summary copied to the clipboard.");
  } catch {
    showFeedback("The browser denied clipboard access.", true);
  }
}

function exportSnapshot() {
  if (latestSnapshot === undefined) return;
  const blob = new Blob([`${JSON.stringify(latestSnapshot, null, 2)}\n`], { type: "application/json" });
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = `ffc-snapshot-${latestSnapshot.snapshot_id}.json`;
  link.click();
  URL.revokeObjectURL(url);
  showFeedback("Validated snapshot exported.");
}

async function refresh() {
  if (refreshing) return;
  refreshing = true;
  const button = byId("refresh");
  button.disabled = true;
  setConnection("", "COLLECTING");
  try {
    const response = await fetch("/api/v1/snapshot", {
      headers: { Accept: "application/json" },
      cache: "no-store",
    });
    const body = await response.json();
    if (!response.ok) throw new Error(body?.error?.message ?? `Snapshot request failed (${response.status}).`);
    render(body, response.headers.get("X-FFC-Snapshot-Source") ?? "fresh");
  } catch (error) {
    text("error-message", error instanceof Error ? error.message : "The local evidence service could not be reached.");
    byId("error-banner").hidden = false;
    setConnection("error", "UNAVAILABLE");
  } finally {
    refreshing = false;
    button.disabled = false;
    scheduleRefresh();
  }
}

byId("refresh").addEventListener("click", () => void refresh());
byId("toggle-refresh").addEventListener("click", toggleAutoRefresh);
byId("copy-summary").addEventListener("click", () => void copySummary());
byId("export-snapshot").addEventListener("click", exportSnapshot);
document.addEventListener("keydown", (event) => {
  if (event.ctrlKey || event.metaKey || event.altKey) return;
  if (event.key.toLowerCase() === "r") {
    event.preventDefault();
    void refresh();
  }
  if (event.key.toLowerCase() === "p") {
    event.preventDefault();
    toggleAutoRefresh();
  }
});
document.addEventListener("visibilitychange", () => {
  if (document.hidden) {
    clearTimeout(refreshTimer);
    updateCountdown();
  } else if (autoRefreshEnabled) {
    void refresh();
  }
});
void refresh();
