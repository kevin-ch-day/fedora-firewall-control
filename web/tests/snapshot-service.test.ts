import assert from "node:assert/strict";
import { test } from "node:test";

import { ApiError } from "../src/server/errors.js";
import {
  SnapshotService,
  type SnapshotCollector,
} from "../src/server/snapshot-service.js";
import { validSnapshot } from "./fixtures/snapshots.js";

test("concurrent requests share one native collection", async () => {
  let calls = 0;
  let release: (() => void) | undefined;
  const gate = new Promise<void>((resolve) => {
    release = resolve;
  });
  const collector: SnapshotCollector = {
    collect: async () => {
      calls += 1;
      await gate;
      return validSnapshot();
    },
  };
  const service = new SnapshotService(collector);
  const first = service.getSnapshot();
  const second = service.getSnapshot();
  assert.deepEqual(service.status(), { cache: "empty", collectionInFlight: true });
  release?.();
  const [firstResult, secondResult] = await Promise.all([first, second]);
  assert.equal(calls, 1);
  assert.deepEqual(firstResult.snapshot, secondResult.snapshot);
  assert.equal(firstResult.source, "fresh");
  assert.equal(secondResult.source, "fresh");
});

test("fresh cache avoids collection and expiry triggers a new collection", async () => {
  let calls = 0;
  let now = 1_000;
  const collector: SnapshotCollector = {
    collect: async () => {
      calls += 1;
      return validSnapshot();
    },
  };
  const service = new SnapshotService(collector, { cacheTtlMs: 2_000, clock: () => now });
  assert.deepEqual(service.status(), { cache: "empty", collectionInFlight: false });
  assert.equal((await service.getSnapshot()).source, "fresh");
  assert.deepEqual(service.status(), { cache: "fresh", collectionInFlight: false });
  now += 1_999;
  assert.equal((await service.getSnapshot()).source, "cache");
  assert.equal(calls, 1);
  now += 1;
  assert.deepEqual(service.status(), { cache: "expired", collectionInFlight: false });
  assert.equal((await service.getSnapshot()).source, "fresh");
  assert.equal(calls, 2);
});

test("clock rollback expires cached evidence instead of extending its lifetime", async () => {
  let calls = 0;
  let now = 5_000;
  const service = new SnapshotService(
    {
      collect: async () => {
        calls += 1;
        return validSnapshot();
      },
    },
    { cacheTtlMs: 2_000, clock: () => now },
  );
  await service.getSnapshot();
  now = 4_999;
  assert.equal(service.status().cache, "expired");
  assert.equal((await service.getSnapshot()).source, "fresh");
  assert.equal(calls, 2);
});

test("collection failure is not converted into an empty successful snapshot", async () => {
  const collector: SnapshotCollector = {
    collect: async () => {
      throw new ApiError("ffc_failed", 503);
    },
  };
  const service = new SnapshotService(collector);
  await assert.rejects(
    service.getSnapshot(),
    (error: unknown) => error instanceof ApiError && error.code === "ffc_failed",
  );
});

test("expired last-known-good data is not returned after refresh failure", async () => {
  let calls = 0;
  let now = 0;
  const collector: SnapshotCollector = {
    collect: async () => {
      calls += 1;
      if (calls === 1) {
        return validSnapshot();
      }
      throw new ApiError("ffc_failed", 503);
    },
  };
  const service = new SnapshotService(collector, { cacheTtlMs: 2_000, clock: () => now });
  await service.getSnapshot();
  now = 2_000;
  await assert.rejects(
    service.getSnapshot(),
    (error: unknown) => error instanceof ApiError && error.code === "ffc_failed",
  );
  assert.equal(calls, 2);
});
