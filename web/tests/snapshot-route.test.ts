import assert from "node:assert/strict";
import { test } from "node:test";

import { buildApp } from "../src/server/app.js";
import { ApiError } from "../src/server/errors.js";
import { TokenBucketRateLimiter } from "../src/server/request-rate-limiter.js";
import { SnapshotService, type SnapshotCollector } from "../src/server/snapshot-service.js";
import { validSnapshot } from "./fixtures/snapshots.js";
import { unavailableSnapshotV2, validSnapshotV2 } from "./fixtures/snapshots-v2.js";

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
    snapshot_provider: {
      configured: true,
      cache: "empty",
      collection_in_flight: false,
    },
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
  assert.equal(first.headers["x-ratelimit-limit"], "30");
  assert.equal(first.headers["x-ratelimit-remaining"], "29");
  assert.equal(second.headers["x-ffc-snapshot-source"], "cache");
  assert.equal(first.headers["x-content-type-options"], "nosniff");
  assert.equal(first.headers["referrer-policy"], "no-referrer");
  assert.equal(first.headers["cross-origin-resource-policy"], "same-origin");
  assert.match(first.headers["content-security-policy"] ?? "", /default-src 'none'/u);
  assert.equal(first.headers["access-control-allow-origin"], undefined);
  assert.deepEqual(first.json(), validSnapshot());
  const health = await app.inject({ method: "GET", url: "/api/v1/health", headers: approvedHeaders });
  assert.equal(health.json().snapshot_provider.cache, "fresh");
  assert.equal(health.json().snapshot_provider.collection_in_flight, false);
});

test("v2 health and snapshot routes expose the parallel structured contract", async (context) => {
  let calls = 0;
  const collector: SnapshotCollector = {
    collect: async () => {
      calls += 1;
      return validSnapshotV2();
    },
  };
  const app = await buildApp({
    snapshotService: new SnapshotService({ collect: async () => validSnapshot() }),
    snapshotV2Service: new SnapshotService(collector),
  });
  context.after(() => app.close());
  const health = await app.inject({ method: "GET", url: "/api/v2/health", headers: approvedHeaders });
  assert.equal(health.statusCode, 200);
  assert.equal(calls, 0);
  assert.deepEqual(health.json(), {
    service: "ffc-web",
    status: "ok",
    api_version: "v2",
    snapshot_schema: "ffc.dashboard.v2",
    access: "loopback-only",
    capabilities: ["read-only", "structured-snapshot"],
    snapshot_provider: {
      configured: true,
      cache: "empty",
      collection_in_flight: false,
    },
  });
  const first = await app.inject({ method: "GET", url: "/api/v2/snapshot", headers: approvedHeaders });
  const second = await app.inject({ method: "GET", url: "/api/v2/snapshot", headers: approvedHeaders });
  assert.equal(first.statusCode, 200);
  assert.equal(first.headers["x-ffc-snapshot-source"], "fresh");
  assert.equal(second.headers["x-ffc-snapshot-source"], "cache");
  assert.equal(first.headers["cache-control"], "no-store, max-age=0");
  assert.equal(first.headers["access-control-allow-origin"], undefined);
  assert.deepEqual(first.json(), validSnapshotV2());
  assert.equal(calls, 1);
});

test("v2 route preserves an unavailable evidence document instead of inventing empty data", async (context) => {
  const app = await buildApp({
    snapshotService: new SnapshotService({ collect: async () => validSnapshot() }),
    snapshotV2Service: new SnapshotService({ collect: async () => unavailableSnapshotV2() }),
  });
  context.after(() => app.close());
  const response = await app.inject({ method: "GET", url: "/api/v2/snapshot", headers: approvedHeaders });
  assert.equal(response.statusCode, 200);
  assert.equal(response.json().status, "unavailable");
  assert.equal(response.json().firewall.runtime_zones, null);
  assert.equal(response.json().listeners.bindings, null);
});

test("v2 snapshot route is explicitly unavailable when its collector is not configured", async (context) => {
  const app = await buildApp({
    snapshotService: new SnapshotService({ collect: async () => validSnapshot() }),
  });
  context.after(() => app.close());
  const health = await app.inject({ method: "GET", url: "/api/v2/health", headers: approvedHeaders });
  assert.equal(health.statusCode, 200);
  assert.equal(health.json().status, "degraded");
  assert.deepEqual(health.json().snapshot_provider, {
    configured: false,
    cache: "unavailable",
    collection_in_flight: false,
  });
  const response = await app.inject({ method: "GET", url: "/api/v2/snapshot", headers: approvedHeaders });
  assert.equal(response.statusCode, 503);
  assert.equal(response.json().error.code, "ffc_unavailable");
});

test("concurrent v2 route requests share one structured native collection", async (context) => {
  let calls = 0;
  let release: (() => void) | undefined;
  const gate = new Promise<void>((resolve) => { release = resolve; });
  const collector: SnapshotCollector = {
    collect: async () => {
      calls += 1;
      await gate;
      return validSnapshotV2();
    },
  };
  const app = await buildApp({
    snapshotService: new SnapshotService({ collect: async () => validSnapshot() }),
    snapshotV2Service: new SnapshotService(collector),
  });
  context.after(() => app.close());
  const first = app.inject({ method: "GET", url: "/api/v2/snapshot", headers: approvedHeaders });
  const second = app.inject({ method: "GET", url: "/api/v2/snapshot", headers: approvedHeaders });
  release?.();
  const responses = await Promise.all([first, second]);
  assert.equal(calls, 1);
  assert.equal(responses[0].statusCode, 200);
  assert.equal(responses[1].statusCode, 200);
  assert.deepEqual(responses[0].json(), responses[1].json());
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

test("cross-site browser requests are rejected before snapshot collection", async (context) => {
  let calls = 0;
  const collector: SnapshotCollector = {
    collect: async () => {
      calls += 1;
      return validSnapshot();
    },
  };
  const app = await buildApp({ snapshotService: new SnapshotService(collector) });
  context.after(() => app.close());
  const response = await app.inject({
    method: "GET",
    url: "/api/v1/snapshot",
    headers: { ...approvedHeaders, "sec-fetch-site": "cross-site" },
  });
  assert.equal(response.statusCode, 403);
  assert.equal(response.json().error.code, "cross_site_request");
  assert.equal(calls, 0);

  const legacyResponse = await app.inject({
    method: "GET",
    url: "/api/v1/snapshot",
    headers: { ...approvedHeaders, origin: "https://attacker.example" },
  });
  assert.equal(legacyResponse.statusCode, 403);
  assert.equal(legacyResponse.json().error.code, "cross_site_request");
  assert.equal(calls, 0);

  const sameOriginResponse = await app.inject({
    method: "GET",
    url: "/api/v1/snapshot",
    headers: { ...approvedHeaders, origin: "http://localhost:8787" },
  });
  assert.equal(sameOriginResponse.statusCode, 200);
  assert.equal(calls, 1);
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
  const v2 = await app.inject({ method: "POST", url: "/api/v2/snapshot", headers: approvedHeaders });
  assert.equal(v2.statusCode, 405);
  assert.equal(v2.headers["allow"], "GET");
  const head = await app.inject({ method: "HEAD", url: "/api/v1/snapshot", headers: approvedHeaders });
  assert.equal(head.statusCode, 405);
  assert.equal(head.headers["allow"], "GET");
});

test("snapshot request bursts are bounded without limiting health checks", async (context) => {
  let now = 0;
  let calls = 0;
  const app = await buildApp({
    snapshotService: new SnapshotService({
      collect: async () => {
        calls += 1;
        return validSnapshot();
      },
    }),
    snapshotRateLimiter: new TokenBucketRateLimiter(2, 60_000, () => now),
  });
  context.after(() => app.close());

  const first = await app.inject({ method: "GET", url: "/api/v1/snapshot", headers: approvedHeaders });
  const second = await app.inject({ method: "GET", url: "/api/v1/snapshot", headers: approvedHeaders });
  const limited = await app.inject({ method: "GET", url: "/api/v1/snapshot", headers: approvedHeaders });
  assert.equal(first.statusCode, 200);
  assert.equal(second.statusCode, 200);
  assert.equal(limited.statusCode, 429);
  assert.equal(limited.headers["retry-after"], "30");
  assert.equal(limited.json().error.code, "rate_limited");
  assert.equal(calls, 1);

  const health = await app.inject({ method: "GET", url: "/api/v1/health", headers: approvedHeaders });
  assert.equal(health.statusCode, 200);
  now += 30_000;
  const refilled = await app.inject({ method: "GET", url: "/api/v1/snapshot", headers: approvedHeaders });
  assert.equal(refilled.statusCode, 200);
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
  const v2 = await app.inject({
    method: "GET",
    url: "/api/v2/snapshot?refresh=true",
    headers: approvedHeaders,
  });
  assert.equal(v2.statusCode, 400);
  assert.equal(v2.json().error.code, "query_not_supported");
});

test("request bodies are rejected before collection", async (context) => {
  let calls = 0;
  const app = await buildApp({
    snapshotService: new SnapshotService({
      collect: async () => {
        calls += 1;
        return validSnapshot();
      },
    }),
  });
  context.after(() => app.close());
  const response = await app.inject({
    method: "GET",
    url: "/api/v1/snapshot",
    headers: { ...approvedHeaders, "content-type": "text/plain" },
    payload: "unexpected request body",
  });
  assert.equal(response.statusCode, 400);
  assert.equal(response.json().error.code, "request_body_not_supported");
  assert.equal(calls, 0);
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
    const app = await buildApp({
      snapshotService: new SnapshotService(collector),
      snapshotV2Service: new SnapshotService(collector),
    });
    context.after(() => app.close());
    for (const url of ["/api/v1/snapshot", "/api/v2/snapshot"]) {
      const response = await app.inject({ method: "GET", url, headers: approvedHeaders });
      assert.equal(response.statusCode, statusCode);
      assert.equal(response.json().error.code, code);
      assert.doesNotMatch(response.body, /\/home\/private|native-secret-stderr/u);
    }
  });
}
