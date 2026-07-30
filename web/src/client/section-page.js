"use strict";

import { compareSnapshots, display, recommendationRoute, titleCase, verificationLabel, yesNo } from "/assets/dashboard-model.js";

const byId = (id) => document.getElementById(id);
const text = (id, value) => { byId(id).textContent = value; };
const page = document.body.dataset.page;
const AUTO_REFRESH_MS = 30_000;
let refreshing = false;
let refreshTimer;
let previousSnapshot;

function setConnection(state, label) {
  const element = byId("connection-state");
  element.className = `connection ${state}`;
  element.lastElementChild.textContent = label;
}

function appendEvidence(target, component) {
  const item = document.createElement("li");
  const name = document.createElement("span");
  const detail = document.createElement("span");
  const status = document.createElement("b");
  name.textContent = component.component;
  detail.className = "evidence-detail";
  detail.textContent = component.detail;
  status.className = `status ${component.status}`;
  status.textContent = component.status.toUpperCase();
  item.append(name, detail, status);
  target.append(item);
}

function renderHome(snapshot) {
  text("home-risk", titleCase(snapshot.risk.level));
  byId("home-risk").className = `tone-${snapshot.risk.level}`;
  text("home-recommendation", snapshot.recommendation.summary);
  const destination = recommendationRoute(snapshot.recommendation.destination);
  byId("home-next-action").href = destination.href;
  text("home-next-action", `${destination.label} →`);
  text("home-firewall", snapshot.firewall.active === true ? "ACTIVE" : snapshot.firewall.active === false ? "INACTIVE" : "UNKNOWN");
  text("home-evidence", titleCase(snapshot.evidence.status));
  text("home-interface", display(snapshot.network.physical_interface));
}

function renderFirewall(snapshot) {
  const firewall = snapshot.firewall;
  const active = firewall.active === true ? "ACTIVE" : firewall.active === false ? "INACTIVE" : "UNKNOWN";
  const enabled = firewall.enabled === true ? "ENABLED" : firewall.enabled === false ? "DISABLED" : "UNKNOWN";
  text("page-status", firewall.active === true ? "Firewalld enforcement active" : firewall.active === false ? "Firewalld enforcement inactive" : "Firewalld state unavailable");
  text("firewall-active", active);
  text("firewall-active-detail", active);
  text("firewall-enabled", enabled);
  text("firewall-enabled-detail", enabled);
  text("firewall-zone", display(firewall.default_zone));
  text("firewall-zone-detail", display(firewall.default_zone));
  text("firewall-interface", display(snapshot.network.physical_interface));
  text("firewall-interface-zone", display(snapshot.network.zone));
  text("firewall-port-rules", display(firewall.inbound_port_rules, "—"));
  text("firewall-protocol-rules", display(firewall.protocol_rules, "—"));
  text("firewall-rich-rules", display(firewall.rich_rules, "—"));
  text("firewall-forwarding", yesNo(firewall.intra_zone_forwarding));
  text("firewall-active-status", titleCase(firewall.active_status));
  text("firewall-enabled-status", titleCase(firewall.enabled_status));
  text("firewall-zone-status", titleCase(firewall.default_zone_status));
  text("firewall-policy-status", titleCase(firewall.policy_status));
}

function renderExposure(snapshot) {
  const firewall = snapshot.firewall;
  const listeners = snapshot.listeners;
  text("page-status", titleCase(snapshot.risk.level));
  text("exposure-bindings", display(listeners.reachable_bindings, "—"));
  text("exposure-bindings-detail", display(listeners.reachable_bindings, "—"));
  text("exposure-ports", display(firewall.inbound_port_rules, "—"));
  text("exposure-ports-detail", display(firewall.inbound_port_rules, "—"));
  text("exposure-risk", titleCase(snapshot.risk.level));
  text("exposure-listeners", display(listeners.tcp_udp_listeners, "—"));
  text("exposure-listener-status", titleCase(listeners.status));
  text("exposure-protocols", display(firewall.protocol_rules, "—"));
  text("exposure-rich-rules", display(firewall.rich_rules, "—"));
  text("exposure-forwarding", yesNo(firewall.intra_zone_forwarding));
  text("exposure-policy-status", titleCase(firewall.policy_status));
  text("exposure-recommendation", snapshot.recommendation.summary);
  text("exposure-severity", `SEVERITY ${titleCase(snapshot.recommendation.severity)}`);
  byId("exposure-severity").className = `meta-chip severity-${snapshot.recommendation.severity}`;
  text("exposure-category", `CATEGORY ${titleCase(snapshot.recommendation.category)}`);
  const destination = recommendationRoute(snapshot.recommendation.destination);
  byId("exposure-destination").href = destination.href;
  text("exposure-destination", `${destination.label} →`);
}

function renderNetwork(snapshot) {
  const network = snapshot.network;
  text("page-status", network.tunnel_detection.tunnel_interface ? "Tunnel interface detected" : "No tunnel interface detected");
  text("network-interface", display(network.physical_interface));
  text("network-interface-detail", display(network.physical_interface));
  text("network-profile", display(network.network_manager.profile));
  text("network-autoconnect", yesNo(network.network_manager.autoconnect));
  text("network-zone", display(network.zone));
  text("network-zone-detail", display(network.zone));
  text("network-tunnel", display(network.tunnel_detection.tunnel_interface, "NONE"));
  text("network-tunnel-detail", display(network.tunnel_detection.tunnel_interface, "NONE DETECTED"));
  text("network-vpn", verificationLabel(network.vpn_route));
  text("network-dns", verificationLabel(network.dns_path));
  text("network-killswitch", yesNo(network.kill_switch.enabled));
  text("network-device-status", titleCase(network.network_manager.device_inventory_status));
  text("network-profile-status", titleCase(network.network_manager.profile_inventory_status));
  text("network-tunnel-status", titleCase(network.tunnel_detection.status));
  text("network-vpn-status", titleCase(network.vpn_route.status));
  text("network-dns-status", titleCase(network.dns_path.status));
  text("network-killswitch-status", titleCase(network.kill_switch.status));
}

function renderEvidence(snapshot) {
  const components = snapshot.evidence.components;
  const attention = components.filter((component) => component.status !== "available");
  const available = components.filter((component) => component.status === "available");
  text("page-status", `${titleCase(snapshot.evidence.status)} evidence`);
  text("evidence-total", components.length);
  text("evidence-available-count", available.length);
  text("evidence-attention-count", attention.length);
  const attentionList = byId("evidence-list");
  const availableList = byId("available-evidence-list");
  attentionList.replaceChildren();
  availableList.replaceChildren();
  if (attention.length === 0) {
    appendEvidence(attentionList, { component: "No evidence gaps reported", detail: "", status: "available" });
  } else {
    for (const component of attention) appendEvidence(attentionList, component);
  }
  for (const component of available) appendEvidence(availableList, component);
}

function renderSession(snapshot) {
  text("session-risk", titleCase(snapshot.risk.level));
  text("session-evidence", titleCase(snapshot.evidence.status));
  text("session-interface", display(snapshot.network.physical_interface));
  text("session-tunnel", display(snapshot.network.tunnel_detection.tunnel_interface, "NONE"));
  const changes = previousSnapshot === undefined ? [] : compareSnapshots(previousSnapshot, snapshot);
  const list = byId("change-list");
  list.replaceChildren();
  text("session-state", previousSnapshot === undefined ? "BASELINE CAPTURED" : changes.length === 0 ? "NO CHANGE" : `${changes.length} CHANGE${changes.length === 1 ? "" : "S"}`);
  if (previousSnapshot === undefined || changes.length === 0) {
    const item = document.createElement("li");
    const time = document.createElement("time");
    const message = document.createElement("span");
    time.textContent = previousSnapshot === undefined ? "NOW" : new Date().toLocaleTimeString();
    message.textContent = previousSnapshot === undefined ? "Baseline captured; monitoring 14 posture signals." : "No monitored posture changes since the previous check.";
    item.append(time, message);
    list.append(item);
  } else {
    for (const change of changes.slice(0, 12)) {
      const item = document.createElement("li");
      const time = document.createElement("time");
      const label = document.createElement("span");
      const transition = document.createElement("b");
      time.textContent = new Date().toLocaleTimeString();
      label.textContent = change.label;
      transition.textContent = `${change.before} → ${change.after}`;
      item.append(time, label, transition);
      list.append(item);
    }
  }
  previousSnapshot = snapshot;
}

function render(snapshot, source) {
  if (page === "home") renderHome(snapshot);
  if (page === "firewall") renderFirewall(snapshot);
  if (page === "network") renderNetwork(snapshot);
  if (page === "exposure") renderExposure(snapshot);
  if (page === "evidence") renderEvidence(snapshot);
  if (page === "session") renderSession(snapshot);
  text("hostname", display(snapshot.hostname, "local host"));
  text("app-version", display(snapshot.application_version, "—"));
  text("snapshot-id", `#${snapshot.snapshot_id}`);
  text("snapshot-source", titleCase(source));
  const collected = new Date(snapshot.collected_at);
  text("collected-at", Number.isNaN(collected.valueOf()) ? snapshot.collected_at : collected.toLocaleString());
  byId("collected-at").dateTime = snapshot.collected_at;
  byId("error-banner").hidden = true;
  setConnection(snapshot.status === "available" ? "ready" : snapshot.status === "partial" ? "partial" : "error", titleCase(snapshot.status));
}

async function refresh() {
  if (refreshing) return;
  refreshing = true;
  byId("refresh").disabled = true;
  setConnection("", "COLLECTING");
  try {
    const response = await fetch("/api/v1/snapshot", { headers: { Accept: "application/json" }, cache: "no-store" });
    const body = await response.json();
    if (!response.ok) throw new Error(body?.error?.message ?? `Snapshot request failed (${response.status}).`);
    render(body, response.headers.get("X-FFC-Snapshot-Source") ?? "fresh");
  } catch (error) {
    text("error-message", error instanceof Error ? error.message : "The local evidence service could not be reached.");
    byId("error-banner").hidden = false;
    setConnection("error", "UNAVAILABLE");
  } finally {
    refreshing = false;
    byId("refresh").disabled = false;
    clearTimeout(refreshTimer);
    if (!document.hidden) refreshTimer = setTimeout(() => void refresh(), AUTO_REFRESH_MS);
  }
}

byId("refresh").addEventListener("click", () => void refresh());
document.addEventListener("keydown", (event) => {
  if (!event.ctrlKey && !event.metaKey && !event.altKey && event.key.toLowerCase() === "r") {
    event.preventDefault();
    void refresh();
  }
});
document.addEventListener("visibilitychange", () => {
  clearTimeout(refreshTimer);
  if (!document.hidden) void refresh();
});
void refresh();
