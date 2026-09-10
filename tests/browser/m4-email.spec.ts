import { expect, test } from "@playwright/test";

const enabled = process.env.GOWEB_BROWSER_E2E === "1";

test.describe("M4 email confirmation and recovery", () => {
  test.skip(!enabled, "set GOWEB_BROWSER_E2E=1 to run browser acceptance specs");

  test("signup reaches confirmation guidance without rendering secrets", async ({ page }) => {
    const email = `browser-${crypto.randomUUID()}@example.test`;
    const password = `browser-${crypto.randomUUID()}-password`;

    await page.goto("/en/sign-up");
    await page.getByLabel("Email").fill(email);
    await page.getByLabel("Password", { exact: true }).fill(password);
    await page.getByRole("button", { name: /create account|sign up/i }).click();

    await expect(page).toHaveURL(/\/en\/(check-inbox|sign-in)/);
    await expect(page.locator("body")).not.toContainText(/password_hash|session[_ -]?id|reset token/i);
  });

  test("password reset request keeps unknown addresses uniform", async ({ page }) => {
    const email = `unknown-${crypto.randomUUID()}@example.test`;

    await page.goto("/en/password-forgotten");
    await page.getByLabel("Email").fill(email);
    await page.getByRole("button", { name: /send|reset|continue/i }).click();

    await expect(page.locator("[role=alert], #alerts")).toContainText(/check|sent|inbox/i);
    await expect(page.locator("body")).not.toContainText(/password_hash|session[_ -]?id|reset token/i);
  });

  test("confirmation and reset failures do not expose credentials", async ({ page }) => {
    for (const path of [
      "/en/confirm-email?token=invalid",
      "/en/password-reset?token=invalid",
    ]) {
      await page.goto(path);
      await expect(page.locator("body")).not.toContainText(/password_hash|session[_ -]?id|client secret/i);
    }
  });
});
