import assert from "node:assert/strict";
import { test } from "node:test";

import { ApiError } from "../src/server/errors.js";
import { DASHBOARD_SCHEMA_PATH_V2, SNAPSHOT_SCHEMA_ID_V2 } from "../src/server/config.js";
import { SnapshotValidator } from "../src/server/schema-validator.js";
import { partialSnapshot, unavailableSnapshot, validSnapshot } from "./fixtures/snapshots.js";
import { partialSnapshotV2, unavailableSnapshotV2, validSnapshotV2 } from "./fixtures/snapshots-v2.js";

test("schema validator accepts valid, partial, and unavailable evidence", async () => {
  const validator = await SnapshotValidator.create();
  for (const snapshot of [validSnapshot(), partialSnapshot(), unavailableSnapshot()]) {
    assert.deepEqual(validator.parseAndValidate(JSON.stringify(snapshot)), snapshot);
  }
});

test("v2 validator accepts structured available, partial, and unavailable evidence", async () => {
  const validator = await SnapshotValidator.create({
    schemaPath: DASHBOARD_SCHEMA_PATH_V2,
    expectedSchemaId: SNAPSHOT_SCHEMA_ID_V2,
  });
  for (const snapshot of [validSnapshotV2(), partialSnapshotV2(), unavailableSnapshotV2()]) {
    assert.deepEqual(validator.parseAndValidate(JSON.stringify(snapshot)), snapshot);
  }
});

test("v2 validator rejects contradictory and unmodeled structured evidence", async () => {
  const validator = await SnapshotValidator.create({
    schemaPath: DASHBOARD_SCHEMA_PATH_V2,
    expectedSchemaId: SNAPSHOT_SCHEMA_ID_V2,
  });
  const contradictory = structuredClone(validSnapshotV2());
  contradictory.listeners.status = "unavailable";
  assert.throws(
    () => validator.parseAndValidate(JSON.stringify(contradictory)),
    (error: unknown) => error instanceof ApiError && error.code === "ffc_schema_invalid",
  );
  const valid = validSnapshotV2();
  const unmodeled = {
    ...valid,
    listeners: {
      ...valid.listeners,
      bindings: [{ ...valid.listeners.bindings[0], command_line: "private --secret" }],
    },
  };
  assert.throws(
    () => validator.parseAndValidate(JSON.stringify(unmodeled)),
    (error: unknown) => error instanceof ApiError && error.code === "ffc_schema_invalid",
  );
});

test("schema validator rejects malformed JSON", async () => {
  const validator = await SnapshotValidator.create();
  assert.throws(
    () => validator.parseAndValidate("{not-json"),
    (error: unknown) => error instanceof ApiError && error.code === "ffc_malformed_output",
  );
});

test("schema validator rejects wrong schema identifiers", async () => {
  const validator = await SnapshotValidator.create();
  const snapshot = { ...validSnapshot(), schema: "ffc.dashboard.v2" };
  assert.throws(
    () => validator.parseAndValidate(JSON.stringify(snapshot)),
    (error: unknown) => error instanceof ApiError && error.code === "ffc_schema_invalid",
  );
});

test("schema validator rejects structurally invalid snapshots", async () => {
  const validator = await SnapshotValidator.create();
  const { risk: _risk, ...snapshot } = validSnapshot();
  assert.throws(
    () => validator.parseAndValidate(JSON.stringify(snapshot)),
    (error: unknown) => error instanceof ApiError && error.code === "ffc_schema_invalid",
  );
});
