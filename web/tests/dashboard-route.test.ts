import assert from "node:assert/strict";
import { test } from "node:test";

import { buildApp } from "../src/server/app.js";
import { SnapshotService, type SnapshotCollector } from "../src/server/snapshot-service.js";
import { validSnapshot } from "./fixtures/snapshots.js";

const approvedHeaders = { host: "127.0.0.1:8787" };

function testApp() {
  const collector: SnapshotCollector = { collect: async () => validSnapshot() };
  return buildApp({ snapshotService: new SnapshotService(collector) });
}

test("root serves the home landing page without collecting a snapshot", async (context) => {
  let calls = 0;
  const collector: SnapshotCollector = {
    collect: async () => {
      calls += 1;
      return validSnapshot();
    },
  };
  const app = await buildApp({ snapshotService: new SnapshotService(collector) });
  context.after(() => app.close());
  const response = await app.inject({ method: "GET", url: "/", headers: approvedHeaders });
  assert.equal(response.statusCode, 200);
  assert.match(response.headers["content-type"] ?? "", /^text\/html/u);
  assert.match(response.body, /Local operations/u);
  assert.match(response.body, /Operations areas/u);
  assert.match(response.body, /\/assets\/dashboard\.css/u);
  assert.match(response.body, /\/assets\/section-page\.js/u);
  assert.match(response.body, /aria-live="polite"/u);
  assert.match(response.body, /class="sidebar"/u);
  assert.match(response.body, /href="\/overview"/u);
  assert.match(response.body, /href="\/firewall"/u);
  assert.match(response.body, /href="\/exposure"/u);
  assert.match(response.body, /id="home-next-action"/u);
  assert.equal(calls, 0);
});

test("overview presents decisions and routes details to focused workflows", async (context) => {
  const app = await testApp();
  context.after(() => app.close());
  const response = await app.inject({ method: "GET", url: "/overview", headers: approvedHeaders });
  assert.equal(response.statusCode, 200);
  assert.match(response.body, /Posture overview/u);
  assert.match(response.body, /What needs attention/u);
  assert.match(response.body, /Snapshot controls/u);
  assert.match(response.body, /Investigation pivots/u);
  assert.match(response.body, /INSPECT ENFORCEMENT/u);
  assert.match(response.body, /INSPECT SURFACE/u);
  assert.match(response.body, /id="recommendation-destination"/u);
  assert.doesNotMatch(response.body, /Inbound rule surface/u);
});

test("dashboard assets use fixed local routes and a self-only CSP", async (context) => {
  const app = await testApp();
  context.after(() => app.close());
  const stylesheet = await app.inject({ method: "GET", url: "/assets/dashboard.css", headers: approvedHeaders });
  const script = await app.inject({ method: "GET", url: "/assets/dashboard.js", headers: approvedHeaders });
  const model = await app.inject({ method: "GET", url: "/assets/dashboard-model.js", headers: approvedHeaders });
  const sectionScript = await app.inject({ method: "GET", url: "/assets/section-page.js", headers: approvedHeaders });
  assert.equal(stylesheet.statusCode, 200);
  assert.match(stylesheet.headers["content-type"] ?? "", /^text\/css/u);
  assert.match(stylesheet.body, /\.error-banner\[hidden\]\s*\{\s*display:\s*none/u);
  assert.match(script.headers["content-type"] ?? "", /^text\/javascript/u);
  assert.equal(model.statusCode, 200);
  assert.equal(sectionScript.statusCode, 200);
  assert.match(model.body, /compareSnapshots/u);
  assert.match(model.body, /operatorGuidance/u);
  assert.match(script.body, /\/api\/v1\/snapshot/u);
  assert.match(script.body, /visibilitychange/u);
  assert.match(script.body, /X-FFC-Snapshot-Source/u);
  assert.match(script.body, /keydown/u);
  assert.match(script.body, /postureSummary/u);
  assert.match(script.body, /ffc-snapshot-/u);
  assert.doesNotMatch(script.body, /\.innerHTML\s*=|\beval\s*\(/u);
  assert.doesNotMatch(sectionScript.body, /\.innerHTML\s*=|\beval\s*\(/u);
  const csp = script.headers["content-security-policy"] ?? "";
  assert.match(csp, /default-src 'none'/u);
  assert.match(csp, /connect-src 'self'/u);
  assert.match(csp, /script-src 'self'/u);
  assert.match(csp, /style-src 'self'/u);
  assert.equal(script.headers["access-control-allow-origin"], undefined);
});

test("all pages have a shared sidebar and one active destination", async (context) => {
  const app = await testApp();
  context.after(() => app.close());
  for (const [url, title, marker] of [
    ["/", "FFC // Home", "Operations areas"],
    ["/overview", "FFC // Posture Overview", "Snapshot controls"],
    ["/firewall", "FFC // Firewall", "Inbound rule surface"],
    ["/network", "FFC // Network Path", "Tunnel verification"],
    ["/exposure", "FFC // Exposure", "Configured ingress"],
    ["/evidence", "FFC // Evidence Coverage", "Collected sources"],
    ["/session", "FFC // Session Watch", "Observed changes"],
  ] as const) {
    const response = await app.inject({ method: "GET", url, headers: approvedHeaders });
    assert.equal(response.statusCode, 200);
    assert.match(response.headers["content-type"] ?? "", /^text\/html/u);
    assert.match(response.body, new RegExp(`<title>${title.replaceAll("/", "\\/")}</title>`, "u"));
    assert.match(response.body, new RegExp(marker, "u"));
    assert.match(response.body, /class="sidebar"/u);
    assert.equal(response.body.match(/aria-current="page"/gu)?.length, 1);
    for (const destination of ["/", "/overview", "/firewall", "/network", "/exposure", "/evidence", "/session"]) {
      assert.match(response.body, new RegExp(`href="${destination}"`, "u"));
    }
  }
});

test("dashboard and asset routes accept only GET without query parameters", async (context) => {
  const app = await testApp();
  context.after(() => app.close());
  const post = await app.inject({ method: "POST", url: "/", headers: approvedHeaders });
  const query = await app.inject({ method: "GET", url: "/?debug=true", headers: approvedHeaders });
  const sectionPost = await app.inject({ method: "POST", url: "/network", headers: approvedHeaders });
  const overviewPost = await app.inject({ method: "POST", url: "/overview", headers: approvedHeaders });
  const firewallPost = await app.inject({ method: "POST", url: "/firewall", headers: approvedHeaders });
  const exposurePost = await app.inject({ method: "POST", url: "/exposure", headers: approvedHeaders });
  assert.equal(post.statusCode, 405);
  assert.equal(post.headers["allow"], "GET");
  assert.equal(query.statusCode, 400);
  assert.equal(sectionPost.statusCode, 405);
  assert.equal(overviewPost.statusCode, 405);
  assert.equal(firewallPost.statusCode, 405);
  assert.equal(exposurePost.statusCode, 405);
});
