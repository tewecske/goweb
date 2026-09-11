import { expect, test } from "@playwright/test";

const enabled = process.env.GOWEB_BROWSER_E2E === "1";

test.describe("M5.2 guest UI", () => {
  test.skip(!enabled, "set GOWEB_BROWSER_E2E=1 to run browser acceptance specs");

  test("guest page views do not create accounts or expose credentials", async ({ page }) => {
    await page.goto("/en/guest/write");
    await expect(page.getByRole("button", { name: /save/i })).toBeVisible();
    await expect(page.locator("[data-guest-banner]")).toHaveCount(0);

    await page.goto("/en/guest/transfer");
    await expect(page.getByLabel(/transfer code/i)).toBeVisible();
    await expect(page.locator('[data-testid="guest-transfer-code"]')).toHaveCount(0);
    await expect(page.locator("body")).not.toContainText(/password_hash|session[_ -]?id|access_token/i);
  });
});
