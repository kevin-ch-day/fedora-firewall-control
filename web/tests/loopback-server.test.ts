import assert from "node:assert/strict";
import { test } from "node:test";

import { buildApp } from "../src/server/app.js";
import { assertNonRoot, LOOPBACK_HOST, SERVER_PORT } from "../src/server/config.js";
import { SnapshotService, type SnapshotCollector } from "../src/server/snapshot-service.js";
import { validSnapshot } from "./fixtures/snapshots.js";

test("server can listen on IPv4 loopback without exposing a wildcard address", async (context) => {
  const collector: SnapshotCollector = { collect: async () => validSnapshot() };
  const app = await buildApp({ snapshotService: new SnapshotService(collector) });
  context.after(() => app.close());
  await app.listen({ host: LOOPBACK_HOST, port: 0 });
  const address = app.server.address();
  assert.notEqual(address, null);
  assert.equal(typeof address, "object");
  if (typeof address === "object" && address !== null) {
    assert.equal(address.address, "127.0.0.1");
  }
  assert.equal(LOOPBACK_HOST, "127.0.0.1");
  assert.equal(SERVER_PORT, 8787);
});

test("root execution is rejected", () => {
  assert.throws(() => assertNonRoot(() => 0), /refuses to run as root/u);
  assert.doesNotThrow(() => assertNonRoot(() => 1000));
});
