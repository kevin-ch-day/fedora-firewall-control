const zone = {
  name: "public",
  applicable: true,
  active: true,
  target: "default",
  interfaces: ["eth0"],
  sources: [],
  services: ["ssh"],
  ports: ["8443/tcp"],
  protocols: [],
  source_ports: [],
  rich_rules: [],
  forward_ports: [],
  masquerade: false,
  forward: false,
  details_valid: true,
};

const evidenceComponents = [
  { component: "firewalld runtime policy", status: "available", detail: "collected" },
  { component: "TCP/UDP listener inventory", status: "available", detail: "collected" },
];

export function validSnapshotV2() {
  const finding = {
    id: "firewall.active-inbound-policy",
    severity: "high",
    category: "firewall_exposure",
    summary: "Review active inbound policy: 1 port rule(s).",
    destination: "firewall.active_openings",
  };
  return {
    schema: "ffc.dashboard.v2",
    schema_version: 2,
    snapshot_id: 2,
    hostname: "test-host",
    application_version: "0.1.2",
    collected_at: "2026-07-29T20:00:00Z",
    age_ms: 0,
    stale: false,
    status: "available",
    assessment: { mode: "normal", defcon_readiness: "not_evaluated" },
    risk: { level: "review_required", blockers: 0, review_items: 1, coverage_gaps: 0 },
    firewall: {
      active_status: "available",
      active: true,
      enabled_status: "available",
      enabled: true,
      default_zone_status: "available",
      default_zone: "public",
      runtime_zones_status: "available",
      permanent_zones_status: "available",
      active_policies_status: "available",
      inbound_port_rules: 1,
      protocol_rules: 0,
      rich_rules: 0,
      intra_zone_forwarding: false,
      runtime_zones: [zone],
      permanent_zones: [zone],
      active_policies: ["allow-host-ipv6"],
      runtime_permanent_drift: [],
    },
    listeners: {
      status: "available",
      tcp_udp_listeners: 1,
      reachable_bindings: 1,
      process_metadata_requested: true,
      bindings: [{
        protocol: "tcp",
        endpoint: "0.0.0.0:8443",
        scope: "network_reachable",
        process_name: "test-service",
      }],
    },
    network: {
      physical_interface: "eth0",
      zone: "public",
      network_manager: {
        device_inventory_status: "available",
        profile_inventory_status: "unavailable",
        profile: null,
        autoconnect: null,
        diagnostic: "profile inventory is not collected",
      },
      tunnel_detection: { status: "available", tunnel_interface: null },
      vpn_route: { status: "unavailable", uses_tunnel: null, diagnostic: "not implemented" },
      dns_path: { status: "unavailable", uses_tunnel: null, diagnostic: "not implemented" },
      kill_switch: { status: "unavailable", enabled: null, diagnostic: "not implemented" },
    },
    findings: { blockers: [], review_items: [finding], coverage_gaps: [] },
    recommendations: [finding],
    recommendation: finding,
    evidence: { status: "available", components: evidenceComponents },
  };
}

export function partialSnapshotV2() {
  const snapshot = structuredClone(validSnapshotV2());
  snapshot.status = "partial";
  snapshot.firewall.runtime_zones_status = "partial";
  snapshot.evidence.status = "partial";
  snapshot.evidence.components.push({
    component: "firewalld runtime policy",
    status: "partial",
    detail: "one zone could not be parsed",
  });
  return snapshot;
}

export function unavailableSnapshotV2() {
  const snapshot = structuredClone(validSnapshotV2());
  return {
    ...snapshot,
    status: "unavailable",
    firewall: {
      active_status: "unavailable",
      active: null,
      enabled_status: "unavailable",
      enabled: null,
      default_zone_status: "unavailable",
      default_zone: null,
      runtime_zones_status: "unavailable",
      permanent_zones_status: "unavailable",
      active_policies_status: "unavailable",
      inbound_port_rules: null,
      protocol_rules: null,
      rich_rules: null,
      intra_zone_forwarding: null,
      runtime_zones: null,
      permanent_zones: null,
      active_policies: null,
      runtime_permanent_drift: null,
    },
    listeners: {
      status: "unavailable",
      tcp_udp_listeners: null,
      reachable_bindings: null,
      process_metadata_requested: false,
      bindings: null,
    },
    evidence: {
      status: "unavailable",
      components: [{ component: "firewalld", status: "unavailable", detail: "not collected" }],
    },
  };
}
