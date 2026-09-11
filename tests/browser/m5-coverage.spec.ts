import { expect, test } from "@playwright/test";

const enabled = process.env.GOWEB_BROWSER_E2E === "1";
const secretPattern = /password_hash|session[_ -]?id|access_token|client_secret|provider_subject/i;
const messageKeyPattern = /(?:auth|recovery|guest|oauth|errors)\.[a-z_.]+/;

test.describe("M5.2 handler and accessibility coverage", () => {
  test.skip(!enabled, "set GOWEB_BROWSER_E2E=1 to run browser acceptance specs");

  for (const language of ["en", "hu"]) {
    test(`${language} public forms have headings, labels, and no literal keys`, async ({ page }) => {
      await page.setViewportSize({ width: 390, height: 844 });
      for (const route of ["/", "/sign-in", "/sign-up", "/forgot-password", "/guest/write", "/guest/transfer", "/guest/upgrade"]) {
        await page.goto(`/${language}${route}`);
        await expect(page.getByRole("heading", { level: 1 })).toHaveCount(1);
        await expect(page.locator("body")).not.toContainText(secretPattern);
        await expect(page.locator("body")).not.toContainText(messageKeyPattern);
        expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBe(true);
      }
    });
  }

  test("full documents and HTMX requests use accessible response shapes", async ({ request }) => {
    const full = await request.get("/en/sign-in");
    expect(full.status()).toBe(200);
    const fullBody = await full.text();
    expect(fullBody).toContain("<!doctype html>");
    expect(fullBody).toContain('id="page-heading"');

    const fragment = await request.get("/en/sign-in", { headers: { "HX-Request": "true" } });
    expect(fragment.status()).toBe(200);
    const fragmentBody = await fragment.text();
    expect(fragmentBody).not.toContain("<!doctype html>");
    expect(fragmentBody).toContain('id="page-content"');
    expect(fragmentBody).toContain('id="page-heading"');
    expect(fragmentBody).not.toMatch(secretPattern);
  });

  test("anonymous theme toggle updates document immediately", async ({ page }) => {
    await page.goto("/en/sign-in");
    await expect(page.locator("html")).toHaveAttribute("data-theme", "light");
    await page.locator('label[title="Toggle theme"]').click();
    await expect(page.locator("html")).toHaveAttribute("data-theme", "dark");
    await page.reload();
    await expect(page.locator("html")).toHaveAttribute("data-theme", "dark");
  });

  test("state-changing request without proof is rejected without echoing secrets", async ({ request }) => {
    const secret = "not-a-real-password-value";
    const response = await request.post("/en/sign-up", {
      form: { email: "user@example.test", password: secret },
    });
    expect(response.status()).toBe(403);
    const body = await response.text();
    expect(body).not.toContain(secret);
    expect(body).not.toMatch(secretPattern);
  });
});
