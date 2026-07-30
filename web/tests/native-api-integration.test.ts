import assert from "node:assert/strict";
import { test } from "node:test";

import { buildApp } from "../src/server/app.js";
import { DASHBOARD_SCHEMA_PATH_V2, SNAPSHOT_SCHEMA_ID_V2 } from "../src/server/config.js";
import { FfcRunner } from "../src/server/ffc-runner.js";
import { SnapshotValidator } from "../src/server/schema-validator.js";
import { NativeSnapshotCollector, SnapshotService } from "../src/server/snapshot-service.js";
import { createExecutableFixture } from "./fixtures/executable.js";
import { validSnapshot } from "./fixtures/snapshots.js";

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

async function v2Validator(): Promise<SnapshotValidator> {
  return SnapshotValidator.create({
    schemaPath: DASHBOARD_SCHEMA_PATH_V2,
    expectedSchemaId: SNAPSHOT_SCHEMA_ID_V2,
  });
}

test("malformed v2 native output maps to a bounded 502 response", async (context) => {
  const fixture = await createExecutableFixture(`
if (process.argv[2] !== "--snapshot-json-v2") process.exit(71);
process.stdout.write("{broken-v2-json");
`);
  context.after(fixture.cleanup);
  const runner = new FfcRunner(fixture.executable, {
    snapshotArgument: "--snapshot-json-v2",
    repositoryRoot: fixture.directory,
    diagnosticLogger: () => undefined,
  });
  const app = await buildApp({
    snapshotService: new SnapshotService({ collect: async () => validSnapshot() }),
    snapshotV2Service: new SnapshotService(new NativeSnapshotCollector(runner, await v2Validator())),
  });
  context.after(() => app.close());
  const response = await app.inject({ method: "GET", url: "/api/v2/snapshot", headers: approvedHeaders });
  assert.equal(response.statusCode, 502);
  assert.equal(response.json().error.code, "ffc_malformed_output");
  assert.doesNotMatch(response.body, /broken-v2-json|ffc-web-test/u);
});

test("oversized v2 native output maps to a bounded 502 response", async (context) => {
  const fixture = await createExecutableFixture("process.stdout.write('x'.repeat(2048));");
  context.after(fixture.cleanup);
  const runner = new FfcRunner(fixture.executable, {
    snapshotArgument: "--snapshot-json-v2",
    maxStdoutBytes: 128,
    repositoryRoot: fixture.directory,
    diagnosticLogger: () => undefined,
  });
  const app = await buildApp({
    snapshotService: new SnapshotService({ collect: async () => validSnapshot() }),
    snapshotV2Service: new SnapshotService(new NativeSnapshotCollector(runner, await v2Validator())),
  });
  context.after(() => app.close());
  const response = await app.inject({ method: "GET", url: "/api/v2/snapshot", headers: approvedHeaders });
  assert.equal(response.statusCode, 502);
  assert.equal(response.json().error.code, "ffc_output_limit");
});

test("v2 native timeout maps to 504 through the complete request pipeline", async (context) => {
  const fixture = await createExecutableFixture("setTimeout(() => process.stdout.write('{}'), 500);");
  context.after(fixture.cleanup);
  const runner = new FfcRunner(fixture.executable, {
    snapshotArgument: "--snapshot-json-v2",
    timeoutMs: 40,
    repositoryRoot: fixture.directory,
    diagnosticLogger: () => undefined,
  });
  const app = await buildApp({
    snapshotService: new SnapshotService({ collect: async () => validSnapshot() }),
    snapshotV2Service: new SnapshotService(new NativeSnapshotCollector(runner, await v2Validator())),
  });
  context.after(() => app.close());
  const response = await app.inject({ method: "GET", url: "/api/v2/snapshot", headers: approvedHeaders });
  assert.equal(response.statusCode, 504);
  assert.equal(response.json().error.code, "ffc_timeout");
});
