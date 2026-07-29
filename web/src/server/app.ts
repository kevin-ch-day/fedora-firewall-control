import helmet from "@fastify/helmet";
import Fastify, { type FastifyInstance } from "fastify";

import {
  API_VERSION,
  APPROVED_HOST_HEADERS,
  DEFAULT_FFC_BINARY,
  SNAPSHOT_SCHEMA_ID,
} from "./config.js";
import { errorDocument, isApiError } from "./errors.js";
import { FfcRunner, resolveFfcExecutable } from "./ffc-runner.js";
import { SnapshotValidator } from "./schema-validator.js";
import { NativeSnapshotCollector, SnapshotService } from "./snapshot-service.js";

export interface BuildAppOptions {
  readonly snapshotService: SnapshotService;
  readonly approvedHostHeaders?: ReadonlySet<string>;
}

function normalizeHostHeader(host: string): string {
  return host.trim().toLowerCase();
}

export async function buildApp(options: BuildAppOptions): Promise<FastifyInstance> {
  const approvedHosts = options.approvedHostHeaders ?? APPROVED_HOST_HEADERS;
  const app = Fastify({
    logger: false,
    bodyLimit: 8 * 1024,
    connectionTimeout: 5_000,
    requestTimeout: 10_000,
    keepAliveTimeout: 5_000,
    maxRequestsPerSocket: 100,
  });

  await app.register(helmet, {
    contentSecurityPolicy: {
      useDefaults: false,
      directives: { defaultSrc: ["'none'"] },
    },
    crossOriginResourcePolicy: { policy: "same-origin" },
    referrerPolicy: { policy: "no-referrer" },
    hsts: false,
  });

  app.addHook("onRequest", async (request, reply) => {
    const host = request.headers.host;
    if (host === undefined || !approvedHosts.has(normalizeHostHeader(host))) {
      await reply.code(421).send({
        error: {
          code: "invalid_host",
          message: "The request Host header is not approved for this local service.",
        },
      });
      return;
    }
    if (request.url.includes("?")) {
      await reply.code(400).send({
        error: {
          code: "query_not_supported",
          message: "Query parameters are not supported by this local service.",
        },
      });
    }
  });

  app.addHook("onSend", async (_request, reply, payload) => {
    void reply.header("Cache-Control", "no-store, max-age=0");
    return payload;
  });

  app.get("/api/v1/health", async () => ({
    service: "ffc-web",
    status: "ok",
    api_version: API_VERSION,
    snapshot_schema: SNAPSHOT_SCHEMA_ID,
    access: "loopback-only",
    capabilities: ["read-only", "snapshot"],
  }));

  app.get("/api/v1/snapshot", async (_request, reply) => {
    const result = await options.snapshotService.getSnapshot();
    void reply.header("X-FFC-Snapshot-Source", result.source);
    return result.snapshot;
  });

  app.setNotFoundHandler(async (request, reply) => {
    if (request.url === "/api/v1/health" || request.url === "/api/v1/snapshot") {
      void reply.header("Allow", "GET");
      return reply.code(405).send({
        error: { code: "method_not_allowed", message: "Only GET is supported for this endpoint." },
      });
    }
    return reply.code(404).send({
      error: { code: "not_found", message: "The requested API endpoint does not exist." },
    });
  });

  app.setErrorHandler(async (error, _request, reply) => {
    if (isApiError(error)) {
      return reply.code(error.statusCode).send(errorDocument(error));
    }
    return reply.code(500).send({
      error: {
        code: "internal_error",
        message: "The local web API encountered an internal error.",
      },
    });
  });

  return app;
}

export async function buildProductionApp(): Promise<FastifyInstance> {
  const executable = await resolveFfcExecutable(process.env["FFC_BIN"] ?? DEFAULT_FFC_BINARY);
  const validator = await SnapshotValidator.create();
  const collector = new NativeSnapshotCollector(new FfcRunner(executable), validator);
  return buildApp({ snapshotService: new SnapshotService(collector) });
}
