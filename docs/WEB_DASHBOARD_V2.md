# Web dashboard v2 contract plan

## Purpose

`ffc.dashboard.v1` intentionally provides bounded posture summaries. The native
core already retains structured firewalld zones and listener records, but v1
reduces them to counts. The next contract should expose enough structure for
the Firewall and Exposure pages to support investigation without implying IDS,
packet-capture, or response capabilities.

Do not add fields to v1 in place. Its schema rejects unknown properties by
design. Introduce v2 as a separate, validated contract and keep v1 available
during migration.

## Proposed additions

### Firewall zones

Expose each applicable runtime zone with:

- name, target, active state, interfaces, and source bindings;
- services, ports, protocols, source ports, and rich rules;
- forwarding, masquerading, and forward ports;
- collection status and whether all modeled dimensions were parsed.

Expose permanent policy separately and provide structured runtime/permanent
drift. Do not flatten drift into one boolean: the UI must identify which zone
and dimension changed.

### Listener bindings

Expose the existing bounded listener inventory with:

- transport protocol and local endpoint;
- loopback-only, multicast-only, or network-reachable scope;
- best-effort process name;
- whether process metadata was requested and whether it was available.

FFC intentionally does not retain command lines or packet contents. PID
collection should remain out of scope until its privacy, privilege, and
lifetime semantics are explicitly designed.

### Findings

Expose every blocker, review item, and coverage gap—not only the highest
priority recommendation. Each finding needs:

- stable identifier;
- severity and category;
- concise summary;
- destination workflow;
- evidence references used to reach the finding.

This enables page-specific findings without recomputing security conclusions
in browser JavaScript.

### Evidence provenance

Each evidence component should eventually include collection time, bounded
duration, collector identifier, and failure class. Raw stderr, executable
paths, command lines, and sensitive diagnostics must remain server-side.

## Correlation boundary

Structured firewall rules and listener bindings may be displayed together,
but record-level correlation requires explicit address, transport, port, zone,
and interface logic. Counts alone must never be labeled as correlated.

The v2 contract must preserve three distinct states:

- configured ingress with no observed listener;
- network-reachable listener with no modeled ingress match;
- listener and policy records that can be defensibly matched.

Unknown or unmodeled policy dimensions prevent a safe correlation result.

## Current milestone

The first parallel-contract milestone is implemented:

- `--snapshot-json` remains unchanged as `ffc.dashboard.v1`;
- `--snapshot-json-v2` emits `ffc.dashboard.v2`;
- v2 includes structured runtime and permanent zones, dimension-level drift,
  active policy names, bounded listener bindings, every finding, and every
  prioritized recommendation;
- unavailable structured inventories serialize as `null`, never false-safe
  empty arrays;
- [the strict v2 schema](../schemas/dashboard-v2.schema.json) is validated
  against live native output in CTest.
- the loopback web service exposes independently validated `/api/v2/health`
  and `/api/v2/snapshot` routes using only the fixed `--snapshot-json-v2`
  native argument;
- v2 has bounded malformed, oversized, timeout, unavailable, cache, and
  concurrent-request coverage without diagnostic leakage.

The browser UI intentionally remains on v1 during this milestone.

## Remaining rollout

1. Render structured zones, listeners, and findings behind focused page tests.
2. Switch the browser UI only after its v2 rendering and fallback behavior has
   full regression coverage.
3. Remove v1 only in a separately documented breaking release.

## Explicit non-goals

- No fabricated Alerts, Hunt, Cases, or PCAP records.
- No remote dashboard binding or browser-selected native commands.
- No firewall mutation through the web service.
- No silent conversion of missing evidence into empty arrays or safe results.
