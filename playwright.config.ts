import { defineConfig, devices } from "@playwright/test";

const browserE2EEnabled = process.env.GOWEB_BROWSER_E2E === "1";
const baseURL = process.env.GOWEB_BROWSER_BASE_URL ?? "http://127.0.0.1:8080";

export default defineConfig({
  testDir: "./tests/browser",
  timeout: 30_000,
  fullyParallel: true,
  forbidOnly: Boolean(process.env.CI),
  retries: process.env.CI ? 2 : 0,
  reporter: "list",
  use: {
    ...devices["Desktop Chrome"],
    baseURL,
    trace: "retain-on-failure",
  },
  webServer: browserE2EEnabled
    ? {
        command: "go run ./cmd/web",
        url: baseURL + "/healthz",
        reuseExistingServer: !process.env.CI,
        timeout: 120_000,
      }
    : undefined,
});
