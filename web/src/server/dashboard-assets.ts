import { readFile } from "node:fs/promises";
import { join } from "node:path";

import { CLIENT_ASSET_ROOT } from "./config.js";
import { ApiError, sanitizeDiagnostic } from "./errors.js";

export interface DashboardAssets {
  readonly homeHtml: string;
  readonly html: string;
  readonly firewallHtml: string;
  readonly networkHtml: string;
  readonly exposureHtml: string;
  readonly evidenceHtml: string;
  readonly sessionHtml: string;
  readonly stylesheet: string;
  readonly script: string;
  readonly sectionScript: string;
  readonly model: string;
}

export async function loadDashboardAssets(assetRoot = CLIENT_ASSET_ROOT): Promise<DashboardAssets> {
  try {
    const [homeHtml, html, firewallHtml, networkHtml, exposureHtml, evidenceHtml, sessionHtml, stylesheet, script, sectionScript, model] = await Promise.all([
      readFile(join(assetRoot, "home.html"), "utf8"),
      readFile(join(assetRoot, "index.html"), "utf8"),
      readFile(join(assetRoot, "firewall.html"), "utf8"),
      readFile(join(assetRoot, "network.html"), "utf8"),
      readFile(join(assetRoot, "exposure.html"), "utf8"),
      readFile(join(assetRoot, "evidence.html"), "utf8"),
      readFile(join(assetRoot, "session.html"), "utf8"),
      readFile(join(assetRoot, "dashboard.css"), "utf8"),
      readFile(join(assetRoot, "dashboard.js"), "utf8"),
      readFile(join(assetRoot, "section-page.js"), "utf8"),
      readFile(join(assetRoot, "dashboard-model.js"), "utf8"),
    ]);
    return { homeHtml, html, firewallHtml, networkHtml, exposureHtml, evidenceHtml, sessionHtml, stylesheet, script, sectionScript, model };
  } catch (error: unknown) {
    throw new ApiError("server_initialization_failed", 500, {
      cause: error,
      diagnostic: sanitizeDiagnostic(error),
    });
  }
}
