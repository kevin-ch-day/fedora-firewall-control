import assert from "node:assert/strict";
import { test } from "node:test";

import { buildApp } from "../src/server/app.js";
import { FfcRunner } from "../src/server/ffc-runner.js";
import { SnapshotValidator } from "../src/server/schema-validator.js";
import { NativeSnapshotCollector, SnapshotService } from "../src/server/snapshot-service.js";
import { createExecutableFixture } from "./fixtures/executable.js";

const approvedHeaders = { host: "127.0.0.1:8787" };

test("malformed native output maps to a bounded 502 response", async (context) => {
  const fixture = await createExecutableFixture("process.stdout.write('{broken-json');");
  context.after(fixture.cleanup);
  const validator = await SnapshotValidator.create();
  const runner = new FfcRunner(fixture.executable, {
    repositoryRoot: fixture.directory,
    diagnosticLogger: () => undefined,
  });
  const app = await buildApp({
    snapshotService: new SnapshotService(new NativeSnapshotCollector(runner, validator)),
  });
  context.after(() => app.close());
  const response = await app.inject({
    method: "GET",
    url: "/api/v1/snapshot",
    headers: approvedHeaders,
  });
  assert.equal(response.statusCode, 502);
  assert.equal(response.json().error.code, "ffc_malformed_output");
  assert.doesNotMatch(response.body, /broken-json|ffc-web-test/u);
});

test("native timeout maps to 504 through the complete request pipeline", async (context) => {
  const fixture = await createExecutableFixture("setTimeout(() => process.stdout.write('{}'), 500);");
  context.after(fixture.cleanup);
  const validator = await SnapshotValidator.create();
  const runner = new FfcRunner(fixture.executable, {
    timeoutMs: 40,
    repositoryRoot: fixture.directory,
    diagnosticLogger: () => undefined,
  });
  const app = await buildApp({
    snapshotService: new SnapshotService(new NativeSnapshotCollector(runner, validator)),
  });
  context.after(() => app.close());
  const response = await app.inject({
    method: "GET",
    url: "/api/v1/snapshot",
    headers: approvedHeaders,
  });
  assert.equal(response.statusCode, 504);
  assert.equal(response.json().error.code, "ffc_timeout");
});

test("a disappeared executable maps to 503 without exposing its path", async (context) => {
  const fixture = await createExecutableFixture("process.stdout.write('{}');");
  const missingPath = `${fixture.executable}-missing`;
  context.after(fixture.cleanup);
  const validator = await SnapshotValidator.create();
  const runner = new FfcRunner(missingPath, {
    repositoryRoot: fixture.directory,
    diagnosticLogger: () => undefined,
  });
  const app = await buildApp({
    snapshotService: new SnapshotService(new NativeSnapshotCollector(runner, validator)),
  });
  context.after(() => app.close());
  const response = await app.inject({
    method: "GET",
    url: "/api/v1/snapshot",
    headers: approvedHeaders,
  });
  assert.equal(response.statusCode, 503);
  assert.equal(response.json().error.code, "ffc_unavailable");
  assert.doesNotMatch(response.body, /ffc-web-test|missing/u);
});
