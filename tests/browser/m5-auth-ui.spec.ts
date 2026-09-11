import { expect, test } from "@playwright/test";

const enabled = process.env.GOWEB_BROWSER_E2E === "1";

test.describe("M5.2 authentication UI", () => {
  test.skip(!enabled, "set GOWEB_BROWSER_E2E=1 to run browser acceptance specs");

  test("localized sign-in page is keyboard-usable and styled without secrets", async ({ page }) => {
    await page.setViewportSize({ width: 390, height: 844 });
    await page.goto("/hu/sign-in");

    await expect(page).toHaveTitle(/Bejelentkezés/);
    await expect(page.getByRole("heading", { level: 1 })).toBeVisible();
    await expect(page.getByLabel(/e-mail|email|felhasznál/i)).toBeVisible();
    await expect(page.getByLabel(/jelszó|password/i)).toBeVisible();
    await expect(page.locator('link[rel="stylesheet"]')).toHaveAttribute("href", "/static/app.css");
    await expect(page.locator('script[src="/static/htmx.min.js"]')).toHaveCount(1);
    await expect(page.locator("form[hx-post]")).toHaveCount(1);
    await expect.poll(() => page.evaluate(() => typeof (window as typeof window & { htmx?: unknown }).htmx)).toBe("object");
    await expect(page.locator("body")).not.toContainText(/password_hash|session[_ -]?id/i);

    await page.getByLabel(/e-mail|email|felhasznál/i).focus();
    await expect(page.getByLabel(/e-mail|email|felhasznál/i)).toBeFocused();
  });

  test("state-changing auth request without CSRF is rejected", async ({ request }) => {
    const response = await request.post("/en/sign-in", {
      form: { identifier: "user@example.test", password: "not-a-real-password" },
    });
    expect(response.status()).toBe(403);
    expect(await response.text()).not.toMatch(/not-a-real-password|password_hash|session[_ -]?id/i);
  });

  test("recovery pages keep bearer tokens out of rendered HTML", async ({ page }) => {
    await page.goto("/en/forgot-password");
    await expect(page.getByLabel(/email/i)).toBeVisible();

    const token = "a".repeat(64);
    await page.goto(`/en/confirm-email?token=${token}`);
    await expect(page.getByRole("heading", { level: 1 })).toBeVisible();
    await expect(page.locator("body")).not.toContainText(token);
  });

  test("unconfigured external providers stay absent and unreachable", async ({ page }) => {
    await page.goto("/en/sign-in");
    await expect(page.locator("[data-oauth-provider]")).toHaveCount(0);
    await page.goto("/en/oauth/github");
    await expect(page.getByRole("heading", { level: 1 })).toContainText(/not found|nem található/i);
    await expect(page.locator("body")).not.toContainText(/client_secret|provider_subject|access_token/i);
  });
});
