import helmet from "@fastify/helmet";
import Fastify, { type FastifyInstance } from "fastify";

import {
  API_VERSION,
  API_VERSION_V2,
  APPROVED_HOST_HEADERS,
  APPROVED_ORIGINS,
  DASHBOARD_SCHEMA_PATH_V2,
  DEFAULT_FFC_BINARY,
  SNAPSHOT_RATE_LIMIT_CAPACITY,
  SNAPSHOT_RATE_LIMIT_WINDOW_MS,
  SNAPSHOT_SCHEMA_ID,
  SNAPSHOT_SCHEMA_ID_V2,
} from "./config.js";
import { loadDashboardAssets, type DashboardAssets } from "./dashboard-assets.js";
import { ApiError, errorDocument, isApiError } from "./errors.js";
import { FfcRunner, resolveFfcExecutable } from "./ffc-runner.js";
import {
  type RequestRateLimiter,
  TokenBucketRateLimiter,
} from "./request-rate-limiter.js";
import { SnapshotValidator } from "./schema-validator.js";
import { NativeSnapshotCollector, SnapshotService } from "./snapshot-service.js";

export interface BuildAppOptions {
  readonly snapshotService: SnapshotService;
  readonly snapshotV2Service?: SnapshotService;
  readonly approvedHostHeaders?: ReadonlySet<string>;
  readonly approvedOrigins?: ReadonlySet<string>;
  readonly dashboardAssets?: DashboardAssets;
  readonly snapshotRateLimiter?: RequestRateLimiter;
}

interface SnapshotApiRoute {
  readonly prefix: "/api/v1" | "/api/v2";
  readonly apiVersion: string;
  readonly schemaId: string;
  readonly capability: "snapshot" | "structured-snapshot";
  readonly service: SnapshotService | undefined;
}

function normalizeHostHeader(host: string): string {
  return host.trim().toLowerCase();
}

const GET_ONLY_ROUTES = new Set([
  "/",
  "/overview",
  "/firewall",
  "/network",
  "/exposure",
  "/evidence",
  "/session",
  "/assets/dashboard.css",
  "/assets/dashboard.js",
  "/assets/dashboard-model.js",
  "/assets/section-page.js",
  "/api/v1/health",
  "/api/v1/snapshot",
  "/api/v2/health",
  "/api/v2/snapshot",
]);

function registerSnapshotApi(app: FastifyInstance, route: SnapshotApiRoute): void {
  app.get(`${route.prefix}/health`, async () => {
    const serviceStatus = route.service?.status();
    return {
      service: "ffc-web",
      status: route.service === undefined ? "degraded" : "ok",
      api_version: route.apiVersion,
      snapshot_schema: route.schemaId,
      access: "loopback-only",
      capabilities: ["read-only", route.capability],
      snapshot_provider: {
        configured: route.service !== undefined,
        cache: serviceStatus?.cache ?? "unavailable",
        collection_in_flight: serviceStatus?.collectionInFlight ?? false,
      },
    };
  });

  app.get(`${route.prefix}/snapshot`, async (_request, reply) => {
    if (route.service === undefined) {
      throw new ApiError("ffc_unavailable", 503);
    }
    const result = await route.service.getSnapshot();
    void reply.header("X-FFC-Snapshot-Source", result.source);
    return result.snapshot;
  });
}

export async function buildApp(options: BuildAppOptions): Promise<FastifyInstance> {
  const approvedHosts = options.approvedHostHeaders ?? APPROVED_HOST_HEADERS;
  const approvedOrigins = options.approvedOrigins ?? APPROVED_ORIGINS;
  const dashboardAssets = options.dashboardAssets ?? (await loadDashboardAssets());
  const snapshotRateLimiter =
    options.snapshotRateLimiter ??
    new TokenBucketRateLimiter(SNAPSHOT_RATE_LIMIT_CAPACITY, SNAPSHOT_RATE_LIMIT_WINDOW_MS);
  const app = Fastify({
    logger: false,
    bodyLimit: 8 * 1024,
    connectionTimeout: 5_000,
    requestTimeout: 10_000,
    handlerTimeout: 12_000,
    keepAliveTimeout: 5_000,
    maxRequestsPerSocket: 100,
    forceCloseConnections: "idle",
    return503OnClosing: true,
    exposeHeadRoutes: false,
    onProtoPoisoning: "error",
    onConstructorPoisoning: "error",
    http: {
      headersTimeout: 5_000,
      requestTimeout: 10_000,
      maxHeaderSize: 8 * 1024,
      insecureHTTPParser: false,
      requireHostHeader: true,
    },
  });

  await app.register(helmet, {
    contentSecurityPolicy: {
      useDefaults: false,
      directives: {
        defaultSrc: ["'none'"],
        baseUri: ["'none'"],
        connectSrc: ["'self'"],
        formAction: ["'none'"],
        frameAncestors: ["'none'"],
        scriptSrc: ["'self'"],
        styleSrc: ["'self'"],
      },
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
    const origin = request.headers.origin;
    if (
      request.headers["sec-fetch-site"] === "cross-site" ||
      (origin !== undefined && !approvedOrigins.has(origin.trim().toLowerCase()))
    ) {
      await reply.code(403).send({
        error: {
          code: "cross_site_request",
          message: "Cross-site browser requests are not permitted by this local service.",
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
      return;
    }
    const contentLength = request.headers["content-length"];
    if (
      request.headers["transfer-encoding"] !== undefined ||
      (contentLength !== undefined && contentLength !== "0")
    ) {
      await reply.code(400).send({
        error: {
          code: "request_body_not_supported",
          message: "Request bodies are not supported by this local service.",
        },
      });
      return;
    }
    if (request.url === "/api/v1/snapshot" || request.url === "/api/v2/snapshot") {
      const decision = snapshotRateLimiter.take();
      void reply.header("X-RateLimit-Limit", decision.limit);
      void reply.header("X-RateLimit-Remaining", decision.remaining);
      if (!decision.allowed) {
        void reply.header("Retry-After", decision.retryAfterSeconds);
        await reply.code(429).send({
          error: {
            code: "rate_limited",
            message: "Snapshot request rate exceeded the local service limit.",
          },
        });
      }
    }
  });

  app.addHook("onSend", async (_request, reply, payload) => {
    void reply.header("Cache-Control", "no-store, max-age=0");
    return payload;
  });

  app.get("/", async (_request, reply) => {
    return reply.type("text/html; charset=utf-8").send(dashboardAssets.homeHtml);
  });

  app.get("/overview", async (_request, reply) => {
    return reply.type("text/html; charset=utf-8").send(dashboardAssets.html);
  });

  app.get("/firewall", async (_request, reply) => {
    return reply.type("text/html; charset=utf-8").send(dashboardAssets.firewallHtml);
  });

  app.get("/network", async (_request, reply) => {
    return reply.type("text/html; charset=utf-8").send(dashboardAssets.networkHtml);
  });

  app.get("/exposure", async (_request, reply) => {
    return reply.type("text/html; charset=utf-8").send(dashboardAssets.exposureHtml);
  });

  app.get("/evidence", async (_request, reply) => {
    return reply.type("text/html; charset=utf-8").send(dashboardAssets.evidenceHtml);
  });

  app.get("/session", async (_request, reply) => {
    return reply.type("text/html; charset=utf-8").send(dashboardAssets.sessionHtml);
  });

  app.get("/assets/dashboard.css", async (_request, reply) => {
    return reply.type("text/css; charset=utf-8").send(dashboardAssets.stylesheet);
  });

  app.get("/assets/dashboard.js", async (_request, reply) => {
    return reply.type("text/javascript; charset=utf-8").send(dashboardAssets.script);
  });

  app.get("/assets/dashboard-model.js", async (_request, reply) => {
    return reply.type("text/javascript; charset=utf-8").send(dashboardAssets.model);
  });

  app.get("/assets/section-page.js", async (_request, reply) => {
    return reply.type("text/javascript; charset=utf-8").send(dashboardAssets.sectionScript);
  });

  registerSnapshotApi(app, {
    prefix: "/api/v1",
    apiVersion: API_VERSION,
    schemaId: SNAPSHOT_SCHEMA_ID,
    capability: "snapshot",
    service: options.snapshotService,
  });
  registerSnapshotApi(app, {
    prefix: "/api/v2",
    apiVersion: API_VERSION_V2,
    schemaId: SNAPSHOT_SCHEMA_ID_V2,
    capability: "structured-snapshot",
    service: options.snapshotV2Service,
  });

  app.setNotFoundHandler(async (request, reply) => {
    if (GET_ONLY_ROUTES.has(request.url)) {
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
  const [validator, validatorV2] = await Promise.all([
    SnapshotValidator.create(),
    SnapshotValidator.create({
      schemaPath: DASHBOARD_SCHEMA_PATH_V2,
      expectedSchemaId: SNAPSHOT_SCHEMA_ID_V2,
    }),
  ]);
  const collector = new NativeSnapshotCollector(new FfcRunner(executable), validator);
  const collectorV2 = new NativeSnapshotCollector(
    new FfcRunner(executable, { snapshotArgument: "--snapshot-json-v2" }),
    validatorV2,
  );
  return buildApp({
    snapshotService: new SnapshotService(collector),
    snapshotV2Service: new SnapshotService(collectorV2),
  });
}
