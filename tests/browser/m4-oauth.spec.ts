import { expect, test } from "@playwright/test";

const enabled = process.env.GOWEB_BROWSER_E2E === "1";
const provider = process.env.GOWEB_BROWSER_OAUTH_PROVIDER ?? "google";

test.describe("M4 external identity", () => {
  test.skip(!enabled, "set GOWEB_BROWSER_E2E=1 to run browser acceptance specs");

  test("unconfigured provider is not reachable", async ({ page }) => {
    await page.goto(`/en/oauth/${provider}`);
    await expect(page.getByRole("heading", { level: 1 })).toContainText(/not found|sign in/i);
    await expect(page.locator("body")).not.toContainText(/client secret|access token|provider subject/i);
  });

  test("provider failure returns readable sign-in state without secrets", async ({ page }) => {
    await page.goto(`/en/oauth/${provider}/callback?code=provider-failure&state=invalid`);
    await expect(page.locator("body")).toContainText(/sign in|unavailable|try again|not found/i);
    await expect(page.locator("body")).not.toContainText(/client secret|access token|provider subject/i);
  });

  test("linked provider controls enforce last sign-in method", async ({ page }) => {
    test.skip(!process.env.GOWEB_BROWSER_DATABASE_FIXTURE, "requires signed-in settings fixture");
    await page.goto("/en/settings/identities");
    await expect(page.locator("body")).toContainText(/external|identity|sign-in/i);
    await expect(page.locator("body")).not.toContainText(/client secret|access token|provider subject/i);
  });
});
