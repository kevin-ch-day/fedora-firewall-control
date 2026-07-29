import { type JsonValue, type ValidatedSnapshot } from "../../src/server/schema-validator.js";

export function validSnapshot(): ValidatedSnapshot {
  return {
    schema: "ffc.dashboard.v1",
    schema_version: 1,
    snapshot_id: 1,
    hostname: "test-host",
    application_version: "0.1.2",
    collected_at: "2026-07-29T20:00:00Z",
    age_ms: 0,
    stale: false,
    status: "available",
    assessment: { mode: "normal", defcon_readiness: "ready" },
    risk: { level: "ready", blockers: 0, review_items: 0, coverage_gaps: 0 },
    firewall: {
      active_status: "available",
      active: true,
      enabled_status: "available",
      enabled: true,
      default_zone_status: "available",
      default_zone: "FedoraWorkstation",
      policy_status: "available",
      inbound_port_rules: 0,
      protocol_rules: 0,
      rich_rules: 0,
      intra_zone_forwarding: false,
    },
    listeners: { status: "available", tcp_udp_listeners: 2, reachable_bindings: 1 },
    network: {
      physical_interface: "eth0",
      zone: "FedoraWorkstation",
      network_manager: {
        device_inventory_status: "available",
        profile_inventory_status: "available",
        profile: "test-profile",
        autoconnect: false,
        diagnostic: "",
      },
      tunnel_detection: { status: "available", tunnel_interface: null },
      vpn_route: { status: "available", uses_tunnel: false, diagnostic: "" },
      dns_path: { status: "available", uses_tunnel: false, diagnostic: "" },
      kill_switch: { status: "available", enabled: false, diagnostic: "" },
    },
    evidence: {
      status: "available",
      components: [{ component: "firewalld", status: "available", detail: "collected" }],
    },
    recommendation: {
      id: "none",
      severity: "information",
      category: "hygiene",
      summary: "No immediate action.",
      destination: "security.overview",
    },
  };
}

export function partialSnapshot(): ValidatedSnapshot {
  const snapshot = validSnapshot();
  return {
    ...snapshot,
    status: "partial",
    firewall: {
      ...(snapshot["firewall"] as Record<string, JsonValue>),
      policy_status: "partial",
    },
    evidence: {
      status: "partial",
      components: [{ component: "policy", status: "partial", detail: "incomplete" }],
    },
  };
}

export function unavailableSnapshot(): ValidatedSnapshot {
  return {
    ...validSnapshot(),
    status: "unavailable",
    firewall: {
      active_status: "unavailable",
      active: null,
      enabled_status: "unavailable",
      enabled: null,
      default_zone_status: "unavailable",
      default_zone: null,
      policy_status: "unavailable",
      inbound_port_rules: null,
      protocol_rules: null,
      rich_rules: null,
      intra_zone_forwarding: null,
    },
    listeners: {
      status: "unavailable",
      tcp_udp_listeners: null,
      reachable_bindings: null,
    },
    evidence: {
      status: "unavailable",
      components: [{ component: "firewalld", status: "unavailable", detail: "not collected" }],
    },
  };
}
