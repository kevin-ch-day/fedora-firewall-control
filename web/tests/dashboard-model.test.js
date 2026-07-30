import assert from "node:assert/strict";
import { test } from "node:test";

import {
  activeState,
  compareSnapshots,
  display,
  freshnessLabel,
  operatorGuidance,
  postureSummary,
  recommendationRoute,
  verificationLabel,
  yesNo,
} from "../src/client/dashboard-model.js";

function snapshot() {
  return {
    stale: false,
    age_ms: 0,
    risk: { level: "ready" },
    assessment: { mode: "normal", defcon_readiness: "ready" },
    evidence: { status: "available" },
    firewall: { active: true, default_zone: "public", inbound_port_rules: 0, rich_rules: 0 },
    listeners: { reachable_bindings: 1 },
    network: {
      physical_interface: "eth0",
      tunnel_detection: { tunnel_interface: null },
      vpn_route: { uses_tunnel: false },
      dns_path: { uses_tunnel: false },
      kill_switch: { enabled: false },
    },
  };
}

test("display helpers preserve explicit false and zero values", () => {
  assert.equal(display(0), "0");
  assert.equal(display(false), "false");
  assert.equal(display(null), "UNKNOWN");
  assert.equal(yesNo(false), "NO");
  assert.equal(activeState(false), "INACTIVE");
});

test("verification and freshness labels distinguish unavailable and stale evidence", () => {
  assert.equal(verificationLabel({ status: "available", uses_tunnel: true }), "THROUGH TUNNEL");
  assert.equal(verificationLabel({ status: "available", uses_tunnel: false }), "DIRECT");
  assert.equal(verificationLabel({ status: "unavailable", uses_tunnel: null }), "UNAVAILABLE");
  assert.equal(freshnessLabel({ stale: true, age_ms: 0 }), "STALE");
  assert.equal(freshnessLabel({ stale: false, age_ms: 7_100 }), "8s OLD");
});

test("recommendations route only to established local workflows", () => {
  assert.deepEqual(recommendationRoute("firewall.active_openings"), { href: "/firewall", label: "Open firewall" });
  assert.deepEqual(recommendationRoute("signals"), { href: "/exposure", label: "Open exposure" });
  assert.deepEqual(recommendationRoute("network"), { href: "/network", label: "Open network" });
  assert.deepEqual(recommendationRoute("evidence"), { href: "/evidence", label: "Open evidence" });
  assert.deepEqual(recommendationRoute("emergency"), { href: "/overview", label: "Open overview" });
  assert.deepEqual(recommendationRoute(undefined), { href: "/overview", label: "Open overview" });
});

test("snapshot comparison reports only meaningful monitored changes", () => {
  const before = snapshot();
  const after = structuredClone(before);
  after.risk.level = "review_required";
  after.firewall.inbound_port_rules = 2;
  after.network.tunnel_detection.tunnel_interface = "nordlynx";
  const changes = compareSnapshots(before, after);
  assert.deepEqual(changes, [
    { label: "Risk level", before: "ready", after: "review_required" },
    { label: "Inbound port rules", before: "0", after: "2" },
    { label: "Tunnel interface", before: "UNKNOWN", after: "nordlynx" },
  ]);
  assert.deepEqual(compareSnapshots(after, structuredClone(after)), []);
});

test("operator guidance distinguishes assessment action, collection failure, and scope gaps", () => {
  const current = snapshot();
  current.assessment.defcon_readiness = "not_evaluated";
  current.evidence.components = [
    { component: "kernel journal", status: "unavailable", detail: "journal query failed" },
    { component: "VPN verification", status: "unavailable", detail: "not implemented" },
  ];
  assert.deepEqual(operatorGuidance(current), [
    {
      kind: "action",
      title: "DEF CON criteria are inactive",
      detail: "Normal mode reports current posture but does not calculate hostile-network readiness.",
      command: "./build/ffc --mode hostile",
    },
    { kind: "warning", title: "1 evidence collection failure", detail: "kernel journal" },
    {
      kind: "limitation",
      title: "1 unassessed area",
      detail: "Treat these values as unknown, not safe: VPN verification",
    },
  ]);
});

test("operator guidance reports a clear collected state without inventing action", () => {
  const current = snapshot();
  current.evidence.components = [{ component: "firewalld", status: "available", detail: "collected" }];
  assert.deepEqual(operatorGuidance(current), [{
    kind: "clear",
    title: "No immediate evidence gaps",
    detail: "All dashboard evidence components were collected. Continue monitoring for posture changes.",
  }]);
});

test("posture summary preserves zero exposure and avoids unavailable diagnostics", () => {
  const current = snapshot();
  current.hostname = "test-host";
  current.risk.blockers = 0;
  current.risk.review_items = 0;
  current.risk.coverage_gaps = 0;
  current.firewall.default_zone = "public";
  current.recommendation = { summary: "No immediate action." };
  current.collected_at = "2026-07-29T22:00:00Z";
  current.snapshot_id = 42;
  const summary = postureSummary(current);
  assert.match(summary, /FFC posture — test-host/u);
  assert.match(summary, /0 blockers, 0 review items/u);
  assert.match(summary, /1 reachable bindings; 0 inbound port rules/u);
  assert.match(summary, /snapshot #42/u);
  assert.doesNotMatch(summary, /diagnostic|stderr|journal query/u);
});
