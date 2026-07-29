import assert from "node:assert/strict";
import { test } from "node:test";

import { buildApp } from "../src/server/app.js";
import { ApiError } from "../src/server/errors.js";
import { SnapshotService, type SnapshotCollector } from "../src/server/snapshot-service.js";
import { validSnapshot } from "./fixtures/snapshots.js";

const approvedHeaders = { host: "localhost:8787" };

test("health is read-only and does not collect a native snapshot", async (context) => {
  let calls = 0;
  const collector: SnapshotCollector = {
    collect: async () => {
      calls += 1;
      return validSnapshot();
    },
  };
  const app = await buildApp({ snapshotService: new SnapshotService(collector) });
  context.after(() => app.close());
  const response = await app.inject({ method: "GET", url: "/api/v1/health", headers: approvedHeaders });
  assert.equal(response.statusCode, 200);
  assert.equal(calls, 0);
  assert.deepEqual(response.json(), {
    service: "ffc-web",
    status: "ok",
    api_version: "v1",
    snapshot_schema: "ffc.dashboard.v1",
    access: "loopback-only",
    capabilities: ["read-only", "snapshot"],
  });
});

test("snapshot route returns validated JSON, cache state, and security headers", async (context) => {
  const collector: SnapshotCollector = { collect: async () => validSnapshot() };
  const app = await buildApp({ snapshotService: new SnapshotService(collector) });
  context.after(() => app.close());
  const first = await app.inject({ method: "GET", url: "/api/v1/snapshot", headers: approvedHeaders });
  const second = await app.inject({ method: "GET", url: "/api/v1/snapshot", headers: approvedHeaders });
  assert.equal(first.statusCode, 200);
  assert.match(first.headers["content-type"] ?? "", /^application\/json/u);
  assert.equal(first.headers["cache-control"], "no-store, max-age=0");
  assert.equal(first.headers["x-ffc-snapshot-source"], "fresh");
  assert.equal(second.headers["x-ffc-snapshot-source"], "cache");
  assert.equal(first.headers["x-content-type-options"], "nosniff");
  assert.equal(first.headers["referrer-policy"], "no-referrer");
  assert.equal(first.headers["cross-origin-resource-policy"], "same-origin");
  assert.match(first.headers["content-security-policy"] ?? "", /default-src 'none'/u);
  assert.equal(first.headers["access-control-allow-origin"], undefined);
  assert.deepEqual(first.json(), validSnapshot());
});

test("host validation rejects unexpected or missing Host headers", async (context) => {
  const collector: SnapshotCollector = { collect: async () => validSnapshot() };
  const app = await buildApp({ snapshotService: new SnapshotService(collector) });
  context.after(() => app.close());
  const unexpected = await app.inject({
    method: "GET",
    url: "/api/v1/health",
    headers: { host: "attacker.example:8787" },
  });
  assert.equal(unexpected.statusCode, 421);
  assert.equal(unexpected.json().error.code, "invalid_host");
});

test("unsupported endpoint methods return 405", async (context) => {
  const collector: SnapshotCollector = { collect: async () => validSnapshot() };
  const app = await buildApp({ snapshotService: new SnapshotService(collector) });
  context.after(() => app.close());
  const response = await app.inject({
    method: "POST",
    url: "/api/v1/snapshot",
    headers: approvedHeaders,
  });
  assert.equal(response.statusCode, 405);
  assert.equal(response.headers["allow"], "GET");
});

test("API endpoints reject query strings", async (context) => {
  const collector: SnapshotCollector = { collect: async () => validSnapshot() };
  const app = await buildApp({ snapshotService: new SnapshotService(collector) });
  context.after(() => app.close());
  const response = await app.inject({
    method: "GET",
    url: "/api/v1/snapshot?refresh=true",
    headers: approvedHeaders,
  });
  assert.equal(response.statusCode, 400);
  assert.equal(response.json().error.code, "query_not_supported");
});

for (const [code, statusCode] of [
  ["ffc_malformed_output", 502],
  ["ffc_schema_invalid", 502],
  ["ffc_output_limit", 502],
  ["ffc_empty_output", 502],
  ["ffc_unavailable", 503],
  ["ffc_permission_denied", 503],
  ["ffc_failed", 503],
  ["ffc_timeout", 504],
] as const) {
  test(`snapshot route maps ${code} without leaking diagnostics`, async (context) => {
    const collector: SnapshotCollector = {
      collect: async () => {
        throw new ApiError(code, statusCode, {
          diagnostic: "/home/private/build/ffc: native-secret-stderr",
        });
      },
    };
    const app = await buildApp({ snapshotService: new SnapshotService(collector) });
    context.after(() => app.close());
    const response = await app.inject({
      method: "GET",
      url: "/api/v1/snapshot",
      headers: approvedHeaders,
    });
    assert.equal(response.statusCode, statusCode);
    assert.equal(response.json().error.code, code);
    assert.doesNotMatch(response.body, /\/home\/private|native-secret-stderr/u);
  });
}
