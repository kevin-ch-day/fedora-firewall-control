"use strict";

export const display = (value, fallback = "UNKNOWN") =>
  value === null || value === undefined || value === "" ? fallback : String(value);

export const yesNo = (value) => value === true ? "YES" : value === false ? "NO" : "UNKNOWN";

export const activeState = (value) =>
  value === true ? "ACTIVE" : value === false ? "INACTIVE" : "UNKNOWN";

export const titleCase = (value) => display(value).replaceAll("_", " ").toUpperCase();

export function verificationLabel(item) {
  if (!item || item.status !== "available") return titleCase(item?.status);
  return item.uses_tunnel === true
    ? "THROUGH TUNNEL"
    : item.uses_tunnel === false ? "DIRECT" : "UNKNOWN";
}

export function freshnessLabel(snapshot) {
  if (snapshot.stale) return "STALE";
  return snapshot.age_ms < 5_000 ? "CURRENT" : `${Math.ceil(snapshot.age_ms / 1000)}s OLD`;
}

const RECOMMENDATION_ROUTES = [
  ["firewall", { href: "/firewall", label: "Open firewall" }],
  ["network", { href: "/network", label: "Open network" }],
  ["evidence", { href: "/evidence", label: "Open evidence" }],
  ["signals", { href: "/exposure", label: "Open exposure" }],
];

export function recommendationRoute(destination) {
  const normalized = typeof destination === "string" ? destination.toLowerCase() : "";
  for (const [prefix, route] of RECOMMENDATION_ROUTES) {
    if (normalized === prefix || normalized.startsWith(`${prefix}.`)) return route;
  }
  return { href: "/overview", label: "Open overview" };
}

const WATCHED_FIELDS = [
  ["Risk level", (snapshot) => snapshot.risk.level],
  ["Assessment mode", (snapshot) => snapshot.assessment.mode],
  ["DEF CON readiness", (snapshot) => snapshot.assessment.defcon_readiness],
  ["Evidence state", (snapshot) => snapshot.evidence.status],
  ["Firewall service", (snapshot) => snapshot.firewall.active],
  ["Firewall zone", (snapshot) => snapshot.firewall.default_zone],
  ["Inbound port rules", (snapshot) => snapshot.firewall.inbound_port_rules],
  ["Rich rules", (snapshot) => snapshot.firewall.rich_rules],
  ["Reachable bindings", (snapshot) => snapshot.listeners.reachable_bindings],
  ["Network interface", (snapshot) => snapshot.network.physical_interface],
  ["Tunnel interface", (snapshot) => snapshot.network.tunnel_detection.tunnel_interface],
  ["VPN route", (snapshot) => snapshot.network.vpn_route.uses_tunnel],
  ["DNS path", (snapshot) => snapshot.network.dns_path.uses_tunnel],
  ["Kill switch", (snapshot) => snapshot.network.kill_switch.enabled],
];

export function compareSnapshots(previous, current) {
  const changes = [];
  for (const [label, read] of WATCHED_FIELDS) {
    const before = read(previous);
    const after = read(current);
    if (!Object.is(before, after)) {
      changes.push({ label, before: display(before), after: display(after) });
    }
  }
  return changes;
}

export function operatorGuidance(snapshot) {
  const guidance = [];
  if (snapshot.assessment.mode === "normal" && snapshot.assessment.defcon_readiness === "not_evaluated") {
    guidance.push({
      kind: "action",
      title: "DEF CON criteria are inactive",
      detail: "Normal mode reports current posture but does not calculate hostile-network readiness.",
      command: "./build/ffc --mode hostile",
    });
  }

  const unavailable = snapshot.evidence.components.filter((component) => component.status === "unavailable");
  const collectionFailures = unavailable.filter((component) => /failed|error|permission|denied/iu.test(component.detail));
  const scopeGaps = unavailable.filter((component) => !collectionFailures.includes(component));
  if (collectionFailures.length > 0) {
    guidance.push({
      kind: "warning",
      title: `${collectionFailures.length} evidence collection ${collectionFailures.length === 1 ? "failure" : "failures"}`,
      detail: collectionFailures.map((component) => component.component).join(", "),
    });
  }
  if (scopeGaps.length > 0) {
    guidance.push({
      kind: "limitation",
      title: `${scopeGaps.length} unassessed ${scopeGaps.length === 1 ? "area" : "areas"}`,
      detail: "Treat these values as unknown, not safe: " + scopeGaps.map((component) => component.component).join(", "),
    });
  }
  if (guidance.length === 0) {
    guidance.push({
      kind: "clear",
      title: "No immediate evidence gaps",
      detail: "All dashboard evidence components were collected. Continue monitoring for posture changes.",
    });
  }
  return guidance;
}

export function postureSummary(snapshot) {
  return [
    `FFC posture — ${display(snapshot.hostname, "local host")}`,
    `Risk: ${titleCase(snapshot.risk.level)} (${snapshot.risk.blockers} blockers, ${snapshot.risk.review_items} review items)`,
    `Assessment: ${titleCase(snapshot.assessment.mode)}; DEF CON readiness ${titleCase(snapshot.assessment.defcon_readiness)}`,
    `Evidence: ${titleCase(snapshot.evidence.status)}; ${snapshot.risk.coverage_gaps} coverage gaps`,
    `Firewall: ${activeState(snapshot.firewall.active)}; zone ${display(snapshot.firewall.default_zone)}`,
    `Exposure: ${display(snapshot.listeners.reachable_bindings)} reachable bindings; ${display(snapshot.firewall.inbound_port_rules)} inbound port rules`,
    `Network: ${display(snapshot.network.physical_interface)}; tunnel ${display(snapshot.network.tunnel_detection.tunnel_interface, "none detected")}`,
    `Recommendation: ${snapshot.recommendation.summary}`,
    `Collected: ${snapshot.collected_at}; snapshot #${snapshot.snapshot_id}`,
  ].join("\n");
}
