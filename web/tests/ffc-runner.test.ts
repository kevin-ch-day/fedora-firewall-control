import assert from "node:assert/strict";
import { chmod } from "node:fs/promises";
import { join } from "node:path";
import { test } from "node:test";

import { ApiError } from "../src/server/errors.js";
import { FfcRunner, resolveFfcExecutable } from "../src/server/ffc-runner.js";
import { createExecutableFixture } from "./fixtures/executable.js";
import { validSnapshot } from "./fixtures/snapshots.js";

test("runner invokes only the fixed snapshot argument without a shell", async (context) => {
  const fixture = await createExecutableFixture(
    `
if (process.argv.length !== 3 || process.argv[2] !== "--snapshot-json") process.exit(71);
process.stdout.write(${JSON.stringify(JSON.stringify(validSnapshot()))});
`,
    { name: "ffc;touch-shell-marker" },
  );
  context.after(fixture.cleanup);
  const executable = await resolveFfcExecutable(fixture.executable);
  const result = await new FfcRunner(executable, {
    repositoryRoot: fixture.directory,
    diagnosticLogger: () => undefined,
  }).runSnapshot();
  assert.equal(result.stdout, JSON.stringify(validSnapshot()));
  await assert.rejects(
    import("node:fs/promises").then(({ access }) => access(join(fixture.directory, "touch-shell-marker"))),
  );
});

test("v2 runner invokes only the fixed structured snapshot argument", async (context) => {
  const fixture = await createExecutableFixture(`
if (process.argv.length !== 3 || process.argv[2] !== "--snapshot-json-v2") process.exit(71);
process.stdout.write("{}");
`);
  context.after(fixture.cleanup);
  const result = await new FfcRunner(fixture.executable, {
    snapshotArgument: "--snapshot-json-v2",
    repositoryRoot: fixture.directory,
    diagnosticLogger: () => undefined,
  }).runSnapshot();
  assert.equal(result.stdout, "{}");
});

test("runner distinguishes nonzero exits", async (context) => {
  const fixture = await createExecutableFixture('process.stderr.write("private-native-detail"); process.exit(9);');
  context.after(fixture.cleanup);
  await assert.rejects(
    new FfcRunner(fixture.executable, {
      repositoryRoot: fixture.directory,
      diagnosticLogger: () => undefined,
    }).runSnapshot(),
    (error: unknown) => error instanceof ApiError && error.code === "ffc_failed",
  );
});

test("runner rejects empty stdout", async (context) => {
  const fixture = await createExecutableFixture("process.stdout.write('   ');");
  context.after(fixture.cleanup);
  await assert.rejects(
    new FfcRunner(fixture.executable, {
      repositoryRoot: fixture.directory,
      diagnosticLogger: () => undefined,
    }).runSnapshot(),
    (error: unknown) => error instanceof ApiError && error.code === "ffc_empty_output",
  );
});

test("runner enforces its timeout", async (context) => {
  const fixture = await createExecutableFixture("setTimeout(() => process.stdout.write('{}'), 500);");
  context.after(fixture.cleanup);
  await assert.rejects(
    new FfcRunner(fixture.executable, {
      timeoutMs: 40,
      repositoryRoot: fixture.directory,
      diagnosticLogger: () => undefined,
    }).runSnapshot(),
    (error: unknown) => error instanceof ApiError && error.code === "ffc_timeout",
  );
});

test("runner enforces stdout and stderr limits", async (context) => {
  const stdoutFixture = await createExecutableFixture("process.stdout.write('x'.repeat(2048));");
  const stderrFixture = await createExecutableFixture(
    "process.stderr.write('x'.repeat(512)); process.stdout.write('{}');",
  );
  context.after(stdoutFixture.cleanup);
  context.after(stderrFixture.cleanup);
  await assert.rejects(
    new FfcRunner(stdoutFixture.executable, {
      maxStdoutBytes: 128,
      maxStderrBytes: 128,
      repositoryRoot: stdoutFixture.directory,
      diagnosticLogger: () => undefined,
    }).runSnapshot(),
    (error: unknown) => error instanceof ApiError && error.code === "ffc_output_limit",
  );
  await assert.rejects(
    new FfcRunner(stderrFixture.executable, {
      maxStdoutBytes: 1024,
      maxStderrBytes: 64,
      repositoryRoot: stderrFixture.directory,
      diagnosticLogger: () => undefined,
    }).runSnapshot(),
    (error: unknown) => error instanceof ApiError && error.code === "ffc_output_limit",
  );
});

test("executable resolution rejects missing, relative, non-executable, and untrusted writable files", async (context) => {
  const fixture = await createExecutableFixture("process.stdout.write('{}');");
  context.after(fixture.cleanup);
  await assert.rejects(resolveFfcExecutable("ffc"));
  await assert.rejects(resolveFfcExecutable(join(fixture.directory, "missing")));
  await chmod(fixture.executable, 0o600);
  await assert.rejects(
    resolveFfcExecutable(fixture.executable),
    (error: unknown) => error instanceof ApiError && error.code === "ffc_permission_denied",
  );
  await chmod(fixture.executable, 0o707);
  await assert.rejects(resolveFfcExecutable(fixture.executable));
  await chmod(fixture.executable, 0o770);
  await assert.rejects(resolveFfcExecutable(fixture.executable));
});
