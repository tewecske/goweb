import { expect, test, type Page } from "@playwright/test";

const enabled = process.env.GOWEB_BROWSER_E2E === "1";
const fixtureEnabled = enabled && Boolean(process.env.GOWEB_DATABASE_URL);

function uniqueEmail(): string {
  return `settings-${crypto.randomUUID()}@example.test`;
}

function uniquePassword(): string {
  return `settings-${crypto.randomUUID()}-password`;
}

async function signUp(page: Page, email: string, password: string): Promise<void> {
  await page.goto("/en/sign-up");
  await page.getByLabel("Email", { exact: true }).fill(email);
  await page.getByLabel("Password", { exact: true }).fill(password);
  await page.getByRole("button", { name: /create account/i }).click();
  await expect(page.getByRole("heading", { level: 1, name: /your home/i })).toBeVisible();
}

test.describe("M6 account settings", () => {
  test.skip(!enabled, "set GOWEB_BROWSER_E2E=1 to run browser acceptance specs");

  test("profile changes persist and reject an invalid username", async ({ page }) => {
    test.skip(!fixtureEnabled, "requires configured database fixture");
    await signUp(page, uniqueEmail(), uniquePassword());

    await page.goto("/en/account/settings");
    await expect(page.getByRole("heading", { level: 1 })).toContainText(/account settings/i);

    const username = `user-${crypto.randomUUID().slice(0, 8)}`;
    await page.getByLabel("Username", { exact: true }).fill("invalid user");
    await page.getByRole("button", { name: /^save$/i }).first().click();
    await expect(page.getByRole("alert").first()).toContainText(/cannot be used/i);

    await page.getByLabel("Username", { exact: true }).fill(username);
    await page.getByLabel("Display name", { exact: true }).fill("Settings Tester");
    await page.getByRole("button", { name: /^save$/i }).first().click();
    await expect(page.getByRole("status").first()).toContainText(/profile updated/i);

    await page.reload();
    await expect(page.getByLabel("Username", { exact: true })).toHaveValue(username);
    await expect(page.getByLabel("Display name", { exact: true })).toHaveValue("Settings Tester");
    await expect(page.locator("body")).not.toContainText(/password_hash|session[_ -]?id/i);
  });

  test("password change requires and validates the current password", async ({ page }) => {
    test.skip(!fixtureEnabled, "requires configured database fixture");
    const password = uniquePassword();
    await signUp(page, uniqueEmail(), password);

    await page.goto("/en/account/settings");
    await page.getByLabel("Current password", { exact: true }).fill("definitely-wrong");
    await page.getByLabel("New password", { exact: true }).fill("replacement-password");
    await page.getByRole("button", { name: /update password/i }).click();
    await expect(page.getByRole("alert").first()).toContainText(/current password is not correct/i);

    await page.getByLabel("Current password", { exact: true }).fill(password);
    await page.getByLabel("New password", { exact: true }).fill("replacement-password");
    await page.getByRole("button", { name: /update password/i }).click();
    await expect(page.getByRole("status").first()).toContainText(/password updated/i);
  });

  test("language preference navigates to the localized settings page", async ({ page }) => {
    test.skip(!fixtureEnabled, "requires configured database fixture");
    await signUp(page, uniqueEmail(), uniquePassword());

    await page.goto("/en/account/settings");
    await page.getByLabel("Language", { exact: true }).selectOption("hu");
    await page.getByRole("button", { name: /^save$/i }).last().click();
    await page.waitForURL("**/hu/account/settings");
    await expect(page.getByRole("heading", { level: 1 })).toContainText(/fiókbeállítások/i);
  });

  test("settings fragments keep authentication and hide credentials", async ({ page }) => {
    test.skip(!fixtureEnabled, "requires configured database fixture");
    await signUp(page, uniqueEmail(), uniquePassword());
    await page.goto("/en/account/settings");
    await expect(page.locator("body")).not.toContainText(/password_hash|session[_ -]?id|argon2/i);
    await expect(page.locator("form[hx-post]").first()).toHaveAttribute("hx-target", "#page-content");
  });
});
