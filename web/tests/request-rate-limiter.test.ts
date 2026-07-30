import assert from "node:assert/strict";
import { test } from "node:test";

import { TokenBucketRateLimiter } from "../src/server/request-rate-limiter.js";

test("token bucket bounds bursts and refills at a deterministic rate", () => {
  let now = 1_000;
  const limiter = new TokenBucketRateLimiter(2, 60_000, () => now);
  assert.deepEqual(limiter.take(), {
    allowed: true,
    limit: 2,
    remaining: 1,
    retryAfterSeconds: 1,
  });
  assert.equal(limiter.take().allowed, true);
  const rejected = limiter.take();
  assert.equal(rejected.allowed, false);
  assert.equal(rejected.remaining, 0);
  assert.equal(rejected.retryAfterSeconds, 30);

  now += 30_000;
  assert.equal(limiter.take().allowed, true);
  assert.equal(limiter.take().allowed, false);
});

test("token bucket ignores clock rollback and validates its bounds", () => {
  let now = 5_000;
  const limiter = new TokenBucketRateLimiter(1, 1_000, () => now);
  assert.equal(limiter.take().allowed, true);
  now = 4_000;
  assert.equal(limiter.take().allowed, false);
  now = 6_000;
  assert.equal(limiter.take().allowed, true);

  assert.throws(() => new TokenBucketRateLimiter(0, 1_000), RangeError);
  assert.throws(() => new TokenBucketRateLimiter(1, Number.NaN), RangeError);
});
