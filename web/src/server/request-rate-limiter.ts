import { performance } from "node:perf_hooks";

export interface RateLimitDecision {
  readonly allowed: boolean;
  readonly limit: number;
  readonly remaining: number;
  readonly retryAfterSeconds: number;
}

export interface RequestRateLimiter {
  take(): RateLimitDecision;
}

export class TokenBucketRateLimiter implements RequestRateLimiter {
  readonly #capacity: number;
  readonly #refillPerMillisecond: number;
  readonly #clock: () => number;
  #tokens: number;
  #updatedAt: number;

  public constructor(
    capacity: number,
    refillWindowMs: number,
    clock: () => number = () => performance.now(),
  ) {
    if (!Number.isSafeInteger(capacity) || capacity <= 0) {
      throw new RangeError("Rate-limit capacity must be a positive safe integer.");
    }
    if (!Number.isFinite(refillWindowMs) || refillWindowMs <= 0) {
      throw new RangeError("Rate-limit refill window must be a positive finite number.");
    }
    this.#capacity = capacity;
    this.#refillPerMillisecond = capacity / refillWindowMs;
    this.#clock = clock;
    this.#tokens = capacity;
    this.#updatedAt = clock();
  }

  public take(): RateLimitDecision {
    const now = this.#clock();
    const elapsed = Math.max(0, now - this.#updatedAt);
    this.#tokens = Math.min(
      this.#capacity,
      this.#tokens + elapsed * this.#refillPerMillisecond,
    );
    this.#updatedAt = Math.max(this.#updatedAt, now);

    const allowed = this.#tokens >= 1;
    if (allowed) {
      this.#tokens -= 1;
    }
    const missingTokens = allowed ? 0 : 1 - this.#tokens;
    return {
      allowed,
      limit: this.#capacity,
      remaining: Math.floor(this.#tokens),
      retryAfterSeconds: Math.max(
        1,
        Math.ceil(missingTokens / this.#refillPerMillisecond / 1_000),
      ),
    };
  }
}
