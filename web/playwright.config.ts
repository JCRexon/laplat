import { defineConfig } from "@playwright/test";

// The harness (e2e/run.sh) boots Postgres + authd + the SvelteKit dev server and
// sets E2E_BASE_URL / E2E_CHROMIUM. We don't use Playwright's `webServer` because
// the stack spans Postgres and authd, which the harness owns.
export default defineConfig({
  testDir: "./e2e",
  timeout: 30_000,
  expect: { timeout: 10_000 },
  reporter: [["list"]],
  use: {
    baseURL: process.env.E2E_BASE_URL ?? "http://localhost:5173",
    launchOptions: process.env.E2E_CHROMIUM ? { executablePath: process.env.E2E_CHROMIUM } : {},
  },
  projects: [{ name: "chromium" }],
});
