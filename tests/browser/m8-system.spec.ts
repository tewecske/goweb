import { expect, test, type Page } from "@playwright/test";

const enabled = process.env.GOWEB_BROWSER_E2E === "1";
const adminEmail = process.env.GOWEB_BOOTSTRAP_ADMIN_EMAIL ?? "";
const adminPassword = process.env.GOWEB_BOOTSTRAP_ADMIN_PASSWORD ?? "";
const adminEnabled =
  enabled &&
  Boolean(process.env.GOWEB_DATABASE_URL) &&
  Boolean(adminEmail) &&
  Boolean(adminPassword);

async function signInAdmin(page: Page): Promise<void> {
  await page.goto("/en/sign-in");
  await page.getByLabel("Email or username", { exact: true }).fill(adminEmail);
  await page.getByLabel("Password", { exact: true }).fill(adminPassword);
  await page.getByRole("button", { name: /^sign in$/i }).click();
  await expect(page.getByRole("heading", { level: 1, name: /your home/i })).toBeVisible();
}

test.describe("M8 system maintenance", () => {
  test.skip(!enabled, "set GOWEB_BROWSER_E2E=1 to run browser acceptance specs");
  test.skip(!adminEnabled, "requires database and bootstrap administrator fixture");

  test("system page shows job health and runs cleanup", async ({ page }) => {
    await signInAdmin(page);

    await page.goto("/en/admin/system");
    await expect(page.getByRole("heading", { level: 1, name: /^system$/i })).toBeVisible();
    await expect(page.getByRole("heading", { name: /background jobs/i })).toBeVisible();
    await expect(page.getByRole("heading", { name: /configuration/i })).toBeVisible();
    await expect(page.getByText(/sign-in rate limit/i)).toBeVisible();
    await expect(page.locator('tr[data-job="guest_cleanup"]')).toBeVisible();
    await expect(page.locator('tr[data-job="token_retention"]')).toBeVisible();
    await expect(page.locator('tr[data-job="login_attempt_retention"]')).toBeVisible();
    await expect(page.locator('tr[data-job="usage_retention"]')).toBeVisible();
    await expect(page.locator("body")).not.toContainText(
      /password_hash|session[_ -]?digest|postgres:\/\/|GOWEB_SESSION_SECRET/i,
    );

    page.once("dialog", (dialog) => dialog.accept());
    await page.getByRole("button", { name: /run cleanup now/i }).click();
    await expect(page.getByText(/cleanup jobs completed\./i)).toBeVisible();
    await expect(page.locator('tr[data-job="guest_cleanup"]')).toBeVisible();

    await page.goto("/en/admin/audit?action=admin.maintenance.run");
    await expect(page.locator("tbody tr").first()).toContainText("admin.maintenance.run");
  });

  test("system page denies non-administrators", async ({ page }) => {
    await page.goto("/en/admin/system");
    await expect(page).toHaveURL(/\/en\/sign-in$/);
  });
});
