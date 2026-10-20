import { defineConfig } from "@playwright/test";

// Guest UI end-to-end flows (issue #76) against a stack you start yourself on free ports, for example
//   cd mvp && API_PORT=8430 UI_PORT=5430 DEVIDP_PORT=8431 TESSERA_DB=/tmp/guests-e2e.db \
//     TESSERA_AUTH_RATE_BURST=5000 TESSERA_ANON_RATE_BURST=5000 ./run.sh --reseed
// then `GUESTS_UI_PORT=5430 GUESTS_DB=/tmp/guests-e2e.db npm run test:e2e:guests` from mvp/frontend
// (GUESTS_DB lets the specs find the dev mail sink, which holds the claim link and the codes). When nothing answers on the UI
// port every spec skips (it never starts or stops a server, so it cannot touch a running dev instance).
const UI = process.env.GUESTS_UI_PORT ?? "5430";

export default defineConfig({
  testDir: "e2e",
  testMatch: /guests\.spec\.ts/,
  timeout: 90_000,
  workers: 1,
  retries: 0,
  reporter: process.env.CI ? [["list"], ["html", { open: "never", outputFolder: "playwright-report" }]] : "list",
  use: { baseURL: `http://localhost:${UI}`, trace: "retain-on-failure" },
});
