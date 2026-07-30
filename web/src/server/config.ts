import { join } from "node:path";
import { fileURLToPath } from "node:url";

export const LOOPBACK_HOST = "127.0.0.1" as const;
export const SERVER_PORT = 8787 as const;
export const SNAPSHOT_SCHEMA_ID = "ffc.dashboard.v1" as const;
export const SNAPSHOT_SCHEMA_ID_V2 = "ffc.dashboard.v2" as const;
export const API_VERSION = "v1" as const;
export const API_VERSION_V2 = "v2" as const;
export const EXECUTION_TIMEOUT_MS = 10_000;
export const MAX_STDOUT_BYTES = 1024 * 1024;
export const MAX_STDERR_BYTES = 64 * 1024;
export const SNAPSHOT_CACHE_TTL_MS = 2_000;
export const SNAPSHOT_RATE_LIMIT_CAPACITY = 30;
export const SNAPSHOT_RATE_LIMIT_WINDOW_MS = 60_000;

export const REPOSITORY_ROOT = fileURLToPath(new URL("../../../", import.meta.url));
export const DEFAULT_FFC_BINARY = join(REPOSITORY_ROOT, "build", "ffc");
export const DASHBOARD_SCHEMA_PATH = join(
  REPOSITORY_ROOT,
  "schemas",
  "dashboard-v1.schema.json",
);
export const DASHBOARD_SCHEMA_PATH_V2 = join(
  REPOSITORY_ROOT,
  "schemas",
  "dashboard-v2.schema.json",
);
export const CLIENT_ASSET_ROOT = fileURLToPath(new URL("../client/", import.meta.url));

export const APPROVED_HOST_HEADERS = new Set([
  `127.0.0.1:${SERVER_PORT}`,
  `localhost:${SERVER_PORT}`,
]);

export const APPROVED_ORIGINS = new Set([
  `http://127.0.0.1:${SERVER_PORT}`,
  `http://localhost:${SERVER_PORT}`,
]);

export function assertNonRoot(getUid: (() => number) | undefined = process.getuid): void {
  if (getUid?.() === 0) {
    throw new Error("The FFC web API refuses to run as root.");
  }
}
