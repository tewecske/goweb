import { expect, test, type Page } from "@playwright/test";

const enabled = process.env.GOWEB_BROWSER_E2E === "1";
const fixtureEnabled = enabled && Boolean(process.env.GOWEB_DATABASE_URL);

function uniqueEmail(): string {
  return `admin-authz-${crypto.randomUUID()}@example.test`;
}

async function signUp(page: Page, email: string, password: string): Promise<void> {
  await page.goto("/en/sign-up");
  await page.getByLabel("Email", { exact: true }).fill(email);
  await page.getByLabel("Password", { exact: true }).fill(password);
  await page.getByRole("button", { name: /create account/i }).click();
  await expect(page.getByRole("heading", { level: 1, name: /your home/i })).toBeVisible();
}

test.describe("M7 administrator authorization", () => {
  test.skip(!enabled, "set GOWEB_BROWSER_E2E=1 to run browser acceptance specs");

  test("anonymous visitors are redirected to sign-in", async ({ page }) => {
    await page.goto("/en/admin");
    await expect(page).toHaveURL(/\/en\/sign-in$/);
  });

  test("non-administrators receive access denied", async ({ page }) => {
    test.skip(!fixtureEnabled, "requires configured database fixture");
    await signUp(page, uniqueEmail(), `admin-authz-${crypto.randomUUID()}-password`);
    await page.goto("/en/admin");
    await expect(page.getByRole("heading", { level: 1, name: /access denied/i })).toBeVisible();
  });
});
