import { expect, test, type Page } from "@playwright/test";

const enabled = process.env.GOWEB_BROWSER_E2E === "1";
const fixtureEnabled = enabled && Boolean(process.env.GOWEB_DATABASE_URL);
const adminEmail = process.env.GOWEB_BOOTSTRAP_ADMIN_EMAIL ?? "";
const adminPassword = process.env.GOWEB_BOOTSTRAP_ADMIN_PASSWORD ?? "";
const adminEnabled =
  fixtureEnabled && Boolean(adminEmail) && Boolean(adminPassword);

function uniqueEmail(prefix: string): string {
  return `${prefix}-${crypto.randomUUID()}@example.test`;
}

function uniquePassword(): string {
  return `a11y-${crypto.randomUUID()}-password`;
}

async function signUp(page: Page, email: string, password: string): Promise<void> {
  await page.goto("/en/sign-up");
  await page.getByLabel("Email", { exact: true }).fill(email);
  await page.getByLabel("Password", { exact: true }).fill(password);
  await page.getByRole("button", { name: /create account/i }).click();
  await expect(page.getByRole("heading", { level: 1, name: /your home/i })).toBeVisible();
}

async function signInAdmin(page: Page): Promise<void> {
  await page.goto("/en/sign-in");
  await page.getByLabel("Email or username", { exact: true }).fill(adminEmail);
  await page.getByLabel("Password", { exact: true }).fill(adminPassword);
  await page.getByRole("button", { name: /^sign in$/i }).click();
  await expect(page.getByRole("heading", { level: 1, name: /your home/i })).toBeVisible();
}

async function unnamedControls(page: Page): Promise<string[]> {
  return page.locator("input:not([type=hidden]), select, textarea").evaluateAll((nodes) =>
    nodes
      .filter((node) => {
        const element = node as HTMLElement;
        const id = element.getAttribute("id");
        const hasLabel = Boolean(id) && Boolean(document.querySelector(`label[for="${id}"]`));
        return !hasLabel && !element.getAttribute("aria-label") && !element.getAttribute("aria-labelledby");
      })
      .map((node) => (node as HTMLElement).outerHTML.slice(0, 120)),
  );
}

test.describe("M9 accessibility smoke", () => {
  test.skip(!enabled, "set GOWEB_BROWSER_E2E=1 to run browser acceptance specs");

  for (const language of ["en", "hu"]) {
    test(`${language} public pages expose one heading, labelled controls, and a live alert region`, async ({ page }) => {
      for (const route of ["/", "/sign-in", "/sign-up", "/forgot-password", "/guest/write", "/guest/transfer", "/guest/upgrade"]) {
        await page.goto(`/${language}${route}`);
        await expect(page.getByRole("heading", { level: 1 })).toHaveCount(1);
        const alerts = page.locator("#alerts");
        await expect(alerts).toHaveAttribute("role", "region");
        await expect(alerts).toHaveAttribute("aria-live", "polite");
        expect(await unnamedControls(page)).toEqual([]);
      }
    });
  }

  test("keyboard users can reach and operate the theme toggle", async ({ page }) => {
    await page.goto("/en/sign-in");
    await page.locator("#theme-toggle").focus();
    await expect(page.locator("#theme-toggle")).toBeFocused();
    await page.keyboard.press("Space");
    await expect(page.locator("html")).toHaveAttribute("data-theme", "dark");
    await page.keyboard.press("Space");
    await expect(page.locator("html")).toHaveAttribute("data-theme", "light");
  });

  test("validation errors surface in the live alert region", async ({ page }) => {
    test.skip(!fixtureEnabled, "requires configured database fixture");
    await signUp(page, uniqueEmail("a11y-alert"), uniquePassword());

    await page.goto("/en/account/settings");
    await page.getByLabel("Username", { exact: true }).fill("invalid user");
    await page
      .locator("section[aria-labelledby='profile-heading']")
      .getByRole("button", { name: /save/i })
      .click();

    const alerts = page.locator("#alerts");
    await expect(alerts.getByRole("alert")).toContainText(/cannot be used/i);
    await expect(page.locator("section[aria-labelledby='profile-heading']").getByRole("button", { name: /save/i })).toBeEnabled();
  });

  test("empty group list exposes an accessible empty state", async ({ page }) => {
    test.skip(!fixtureEnabled, "requires configured database fixture");
    await signUp(page, uniqueEmail("a11y-empty"), uniquePassword());

    await page.goto("/en/groups");
    await expect(page.getByRole("heading", { level: 1 })).toHaveCount(1);
    await expect(page.getByText(/not in any group yet/i)).toBeVisible();
    await expect(page.getByRole("radio", { name: /create/i })).toBeVisible();
  });

  test("destructive administrator action requires a browser confirmation dialog", async ({ page }) => {
    test.skip(!adminEnabled, "requires database and bootstrap administrator fixture");
    await signInAdmin(page);
    const email = uniqueEmail("a11y-dialog");
    await page.goto("/en/admin/users/new");
    await page.locator("#admin-account-email").fill(email);
    await page.locator("#admin-account-password").fill(uniquePassword());
    await page.getByRole("button", { name: /^create account$/i }).click();
    await expect(page).toHaveURL(/\/en\/admin\/users$/);

    await page.goto(`/en/admin/users?q=${encodeURIComponent(email)}`);
    await page.locator("tbody tr").filter({ hasText: email }).first().getByRole("link", { name: /^edit$/i }).click();
    await expect(page.locator("#admin-account-email")).toHaveValue(email);

    const confirm = page.locator("#admin-account-confirm-delete");
    await expect(confirm).toBeVisible();
    await expect(confirm).toHaveAttribute("required", "");
    await expect(page.getByText(/permanently deletes the account/i).first()).toBeVisible();
    await confirm.check();
    await expect(confirm).toBeChecked();

    // The destructive action is confirmed in the browser before it is sent.
    page.once("dialog", (dialog) => dialog.accept());
    await page.getByRole("button", { name: /^delete account$/i }).click();
    await expect(page).toHaveURL(/\/en\/admin\/users$/);
    await expect(page.locator("tbody tr").filter({ hasText: email })).toHaveCount(0);
  });
});
