import { defineConfig } from "@playwright/test";
import { tmpdir } from "node:os";
import { join } from "node:path";

// Accessibility and keyboard tests (issue #173) against the real stack:
// run.sh builds and starts the dev IdP, the API (seeded demo tenant) and the
// UI on their own ports, so they never touch a running dev instance.
const UI = process.env.A11Y_UI_PORT ?? "5610";
const API = process.env.A11Y_API_PORT ?? "8610";
const IDP = process.env.A11Y_IDP_PORT ?? "8611";

export default defineConfig({
  testDir: "e2e",
  timeout: 90_000,
  workers: 1,
  retries: 0,
  reporter: process.env.CI ? [["list"], ["html", { open: "never", outputFolder: "playwright-report" }]] : "list",
  use: { baseURL: `http://localhost:${UI}`, trace: "retain-on-failure" },
  projects: [
    { name: "setup", testMatch: /auth\.setup\.ts/ },
    // route checks reuse the setup's session; the keyboard walkthrough signs in itself
    { name: "a11y", testMatch: /(a11y|wcag22)\.spec\.ts/, dependencies: ["setup"] },
    { name: "keyboard", testMatch: /keyboard\.spec\.ts/ },
    // phone and tablet widths (issue #174)
    { name: "mobile", testMatch: /mobile\.spec\.ts/, dependencies: ["setup"] },
  ],
  webServer: {
    command: "../run.sh --reseed",
    url: `http://localhost:${UI}/`,
    timeout: 300_000,
    reuseExistingServer: false,
    stdout: "ignore",
    stderr: "pipe",
    env: {
      API_PORT: API, UI_PORT: UI, DEVIDP_PORT: IDP,
      // every page load calls /api/auth/session from the same address
      TESSERA_AUTH_RATE_BURST: "5000", TESSERA_ANON_RATE_BURST: "5000",
      TESSERA_DB: process.env.A11Y_DB ?? join(tmpdir(), `tessera-a11y-${process.pid}.db`),
    },
  },
});
