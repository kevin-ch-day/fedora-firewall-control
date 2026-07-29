import { SNAPSHOT_CACHE_TTL_MS } from "./config.js";
import { type FfcRunner } from "./ffc-runner.js";
import { type SnapshotValidator, type ValidatedSnapshot } from "./schema-validator.js";

export interface SnapshotCollector {
  collect(): Promise<ValidatedSnapshot>;
}

export type SnapshotSource = "fresh" | "cache";

export interface SnapshotResult {
  readonly snapshot: ValidatedSnapshot;
  readonly source: SnapshotSource;
}

export class NativeSnapshotCollector implements SnapshotCollector {
  readonly #runner: FfcRunner;
  readonly #validator: SnapshotValidator;

  public constructor(runner: FfcRunner, validator: SnapshotValidator) {
    this.#runner = runner;
    this.#validator = validator;
  }

  public async collect(): Promise<ValidatedSnapshot> {
    const result = await this.#runner.runSnapshot();
    return this.#validator.parseAndValidate(result.stdout);
  }
}

export class SnapshotService {
  readonly #collector: SnapshotCollector;
  readonly #cacheTtlMs: number;
  readonly #clock: () => number;
  #cached: { snapshot: ValidatedSnapshot; collectedAt: number } | undefined;
  #inFlight: Promise<ValidatedSnapshot> | undefined;

  public constructor(
    collector: SnapshotCollector,
    options: { cacheTtlMs?: number; clock?: () => number } = {},
  ) {
    this.#collector = collector;
    this.#cacheTtlMs = options.cacheTtlMs ?? SNAPSHOT_CACHE_TTL_MS;
    this.#clock = options.clock ?? Date.now;
  }

  public async getSnapshot(): Promise<SnapshotResult> {
    const now = this.#clock();
    if (this.#cached !== undefined && now - this.#cached.collectedAt < this.#cacheTtlMs) {
      return { snapshot: this.#cached.snapshot, source: "cache" };
    }
    if (this.#inFlight !== undefined) {
      return { snapshot: await this.#inFlight, source: "fresh" };
    }

    const collection = this.#collector.collect();
    this.#inFlight = collection;
    try {
      const snapshot = await collection;
      this.#cached = { snapshot, collectedAt: this.#clock() };
      return { snapshot, source: "fresh" };
    } finally {
      if (this.#inFlight === collection) {
        this.#inFlight = undefined;
      }
    }
  }
}
