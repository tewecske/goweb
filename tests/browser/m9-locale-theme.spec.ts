import { expect, test, type Page } from "@playwright/test";

const enabled = process.env.GOWEB_BROWSER_E2E === "1";
const fixtureEnabled = enabled && Boolean(process.env.GOWEB_DATABASE_URL);
const baseURL = process.env.GOWEB_BROWSER_BASE_URL ?? "http://127.0.0.1:8080";

function uniqueEmail(): string {
  return `locale-${crypto.randomUUID()}@example.test`;
}

function uniquePassword(): string {
  return `locale-${crypto.randomUUID()}-password`;
}

async function signUp(page: Page, email: string, password: string): Promise<void> {
  await page.goto("/en/sign-up");
  await page.getByLabel("Email", { exact: true }).fill(email);
  await page.getByLabel("Password", { exact: true }).fill(password);
  await page.getByRole("button", { name: /create account/i }).click();
  await expect(page.getByRole("heading", { level: 1, name: /your home/i })).toBeVisible();
}

test.describe("M9 locale selection", () => {
  test.skip(!enabled, "set GOWEB_BROWSER_E2E=1 to run browser acceptance specs");

  test.describe("browser language fallback", () => {
    test.use({ locale: "hu-HU" });

    test("supported browser language selects the matching prefix", async ({ page }) => {
      await page.goto("/");
      await expect(page).toHaveURL(/\/hu\/$/);
      await expect(page.locator("html")).toHaveAttribute("lang", "hu");
    });
  });

  test.describe("unsupported browser language", () => {
    test.use({ locale: "fr-FR" });

    test("falls back to the default language", async ({ page }) => {
      await page.goto("/");
      await expect(page).toHaveURL(/\/en\/$/);
      await expect(page.locator("html")).toHaveAttribute("lang", "en");
    });
  });

  test.describe("browser language precedence", () => {
    test.use({ locale: "en-US" });

    test("a stored language preference wins over the request language", async ({ page }) => {
      await page.context().addCookies([{ name: "goweb_locale", value: "hu", url: baseURL }]);
      await page.goto("/");
      await expect(page).toHaveURL(/\/hu\/$/);
    });

    test("an unsupported stored language falls back to the default", async ({ page }) => {
      await page.context().addCookies([{ name: "goweb_locale", value: "de", url: baseURL }]);
      await page.goto("/");
      await expect(page).toHaveURL(/\/en\/$/);
    });

    test("an explicit URL prefix wins over the request language", async ({ page }) => {
      await page.goto("/en/");
      await expect(page).toHaveURL(/\/en\/$/);
      await expect(page.locator("html")).toHaveAttribute("lang", "en");
      await page.goto("/hu/");
      await expect(page.locator("html")).toHaveAttribute("lang", "hu");
    });
  });

  test("deep links with a language prefix render the requested page", async ({ page }) => {
    await page.goto("/hu/sign-in");
    await expect(page.getByRole("heading", { level: 1 })).toHaveCount(1);
    await expect(page.getByRole("heading", { level: 1 })).not.toContainText(/not found/i);
    await expect(page.locator('input#identifier')).toBeVisible();
    await expect(page.locator("html")).toHaveAttribute("lang", "hu");
  });

  test("a language prefix without a trailing slash is canonicalized", async ({ page }) => {
    await page.goto("/hu");
    await expect(page).toHaveURL(/\/hu\/$/);
  });

  test("an unsupported language prefix is not-found", async ({ page }) => {
    const response = await page.goto("/fr/");
    expect(response?.status()).toBe(404);
    await expect(page.locator("body")).toContainText(/not found/i);
  });
});

test.describe("M9 theme persistence", () => {
  test.skip(!enabled, "set GOWEB_BROWSER_E2E=1 to run browser acceptance specs");

  test("an anonymous theme choice persists through browser storage", async ({ page }) => {
    await page.goto("/en/sign-in");
    await expect(page.locator("html")).toHaveAttribute("data-theme", "light");
    await page.locator('label[title="Toggle theme"]').click();
    await expect(page.locator("html")).toHaveAttribute("data-theme", "dark");
    await page.reload();
    await expect(page.locator("html")).toHaveAttribute("data-theme", "dark");
  });

  test("an authenticated theme choice persists through the server", async ({ page }) => {
    test.skip(!fixtureEnabled, "requires configured database fixture");
    await signUp(page, uniqueEmail(), uniquePassword());
    await page.goto("/en/account/settings");
    await expect(page.locator("html")).toHaveAttribute("data-theme", "light");

    const update = page.waitForResponse((response) => response.url().endsWith("/en/account/theme"));
    await page.locator('label[title="Toggle theme"]').click();
    expect((await update).status()).toBe(204);
    await expect(page.locator("html")).toHaveAttribute("data-theme", "dark");

    await page.reload();
    await expect(page.locator("html")).toHaveAttribute("data-theme", "dark");
    await expect(page.locator("html")).toHaveAttribute("data-account-theme", "dark");
  });

  test("a rejected authenticated theme change reverts the interface", async ({ page }) => {
    test.skip(!fixtureEnabled, "requires configured database fixture");
    await signUp(page, uniqueEmail(), uniquePassword());
    await page.goto("/en/account/settings");

    const update = page.waitForResponse((response) => response.url().endsWith("/en/account/theme"));
    await page.locator('label[title="Toggle theme"]').click();
    expect((await update).status()).toBe(204);
    await expect(page.locator("html")).toHaveAttribute("data-theme", "dark");

    await page.route("**/en/account/theme", (route) => route.fulfill({ status: 500, body: "" }));
    const rejected = page.waitForResponse((response) => response.url().endsWith("/en/account/theme"));
    await page.locator('label[title="Toggle theme"]').click();
    expect((await rejected).status()).toBe(500);

    await expect(page.locator("html")).toHaveAttribute("data-theme", "dark");
    await expect(page.locator("#theme-toggle")).toBeChecked();
    await page.reload();
    await expect(page.locator("html")).toHaveAttribute("data-theme", "dark");
  });
});
