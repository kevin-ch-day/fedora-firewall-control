import assert from "node:assert/strict";
import { test } from "node:test";

import { ApiError } from "../src/server/errors.js";
import { SnapshotValidator } from "../src/server/schema-validator.js";
import { partialSnapshot, unavailableSnapshot, validSnapshot } from "./fixtures/snapshots.js";

test("schema validator accepts valid, partial, and unavailable evidence", async () => {
  const validator = await SnapshotValidator.create();
  for (const snapshot of [validSnapshot(), partialSnapshot(), unavailableSnapshot()]) {
    assert.deepEqual(validator.parseAndValidate(JSON.stringify(snapshot)), snapshot);
  }
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
