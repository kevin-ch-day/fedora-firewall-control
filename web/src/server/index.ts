import { pathToFileURL } from "node:url";

import { buildProductionApp } from "./app.js";
import { assertNonRoot, LOOPBACK_HOST, SERVER_PORT } from "./config.js";
import { sanitizeDiagnostic } from "./errors.js";

export async function main(): Promise<void> {
  assertNonRoot();
  const app = await buildProductionApp();
  let closing = false;

  const shutdown = async (signal: NodeJS.Signals): Promise<void> => {
    if (closing) {
      return;
    }
    closing = true;
    console.log(`\nStopping FFC web API (${signal})...`);
    await app.close();
  };

  process.once("SIGINT", () => void shutdown("SIGINT"));
  process.once("SIGTERM", () => void shutdown("SIGTERM"));

  try {
    await app.listen({ host: LOOPBACK_HOST, port: SERVER_PORT });
  } catch (error: unknown) {
    await app.close();
    throw error;
  }

  console.log("FFC web API");
  console.log(`Address: http://${LOOPBACK_HOST}:${SERVER_PORT}`);
  console.log("Access: local browser only");
  console.log("Mode: read-only");
}

const entryPoint = process.argv[1];
if (entryPoint !== undefined && import.meta.url === pathToFileURL(entryPoint).href) {
  main().catch((error: unknown) => {
    console.error(`FFC web API startup failed: ${sanitizeDiagnostic(error)}`);
    process.exitCode = 1;
  });
}
