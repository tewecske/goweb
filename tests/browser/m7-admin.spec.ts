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
  return `admin-${crypto.randomUUID()}-password`;
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

async function createAccount(page: Page, email: string, password: string): Promise<void> {
  await page.goto("/en/admin/users/new");
  await page.locator("#admin-account-email").fill(email);
  await page.locator("#admin-account-password").fill(password);
  await page.getByRole("button", { name: /^create account$/i }).click();
  await expect(page).toHaveURL(/\/en\/admin\/users$/);
  await expect(page.locator(`tbody tr:has-text("${email}")`)).toBeVisible();
}

function accountRow(page: Page, email: string) {
  return page.locator("tbody tr").filter({ hasText: email }).first();
}

test.describe("M7 administrator authorization", () => {
  test.skip(!enabled, "set GOWEB_BROWSER_E2E=1 to run browser acceptance specs");

  test("anonymous visitors are redirected to sign-in", async ({ page }) => {
    await page.goto("/en/admin");
    await expect(page).toHaveURL(/\/en\/sign-in$/);
  });

  test("non-administrators receive access denied", async ({ page }) => {
    test.skip(!fixtureEnabled, "requires configured database fixture");
    await signUp(page, uniqueEmail("admin-authz"), uniquePassword());
    await page.goto("/en/admin");
    await expect(page.getByRole("heading", { level: 1, name: /access denied/i })).toBeVisible();
  });
});

test.describe("M7 administrator workflows", () => {
  test.skip(!enabled, "set GOWEB_BROWSER_E2E=1 to run browser acceptance specs");
  test.skip(!adminEnabled, "requires database and bootstrap administrator fixture");

  test("search, paging, diagnostics, provider-safe detail, and session revocation", async ({ browser, page }) => {
    await signInAdmin(page);
    const email = uniqueEmail("admin-detail");
    const password = uniquePassword();
    await createAccount(page, email, password);

    // URL state: searching narrows to exactly one result.
    await page.goto(`/en/admin/users?q=${encodeURIComponent(email)}`);
    await expect(page.locator("tbody tr[data-account-id]")).toHaveCount(1);

    // The target signs in on another device to create an active session.
    const memberContext = await browser.newContext();
    const memberPage = await memberContext.newPage();
    try {
      await memberPage.goto("/en/sign-in");
      await memberPage.getByLabel("Email or username", { exact: true }).fill(email);
      await memberPage.getByLabel("Password", { exact: true }).fill(password);
      await memberPage.getByRole("button", { name: /^sign in$/i }).click();
      await expect(memberPage.getByRole("heading", { level: 1, name: /your home/i })).toBeVisible();

      await page.goto(`/en/admin/users?q=${encodeURIComponent(email)}`);
      await accountRow(page, email).getByRole("link", { name: /^view$/i }).click();
      await expect(page.getByRole("heading", { level: 1, name: email })).toBeVisible();
      await expect(page.getByRole("heading", { name: /active sessions/i })).toBeVisible();
      await expect(page.getByTestId("session-count")).toHaveText("1");
      await expect(page.getByRole("heading", { name: /recent sign-in attempts/i })).toBeVisible();
      await expect(page.getByRole("heading", { name: /linked providers/i })).toBeVisible();
      await expect(page.getByRole("heading", { name: /lockout/i })).toBeVisible();
      await expect(page.locator("body")).not.toContainText(/password_hash|session[_ -]?digest|super-secret/i);

      // Administrator-created accounts start confirmed; a fresh link can be sent.
      await expect(page.getByText(/email confirmed/i).first()).toBeVisible();
      await page.getByRole("button", { name: /send confirmation link/i }).click();
      await expect(page.getByText(/confirmation link sent\./i)).toBeVisible();

      // Lockout clearing is audited and safe on a clear account.
      page.once("dialog", (dialog) => dialog.accept());
      await page.getByRole("button", { name: /clear lockout/i }).click();
      await expect(page.getByText(/lockout cleared\./i)).toBeVisible();

      // Session revocation re-reads authoritative state and ends the session.
      page.once("dialog", (dialog) => dialog.accept());
      await page.getByRole("button", { name: /end all sessions/i }).click();
      await expect(page.getByText(/all sessions ended\./i)).toBeVisible();
      await memberPage.goto("/en/home");
      await expect(memberPage).toHaveURL(/\/en\/sign-in$/);
    } finally {
      await memberContext.close();
    }
  });

  test("editing, self-protection, and deletion", async ({ page }) => {
    await signInAdmin(page);
    const email = uniqueEmail("admin-edit");
    const updated = uniqueEmail("admin-edited");
    await createAccount(page, email, uniquePassword());

    await accountRow(page, email).getByRole("link", { name: /^edit$/i }).click();
    await page.locator("#admin-account-email").fill(updated);
    await page.locator("#admin-account-is-admin").check();
    await page.getByRole("button", { name: /save changes/i }).click();
    await expect(page.getByRole("heading", { level: 1, name: updated })).toBeVisible();
    await expect(page.getByText(/administrator/i).first()).toBeVisible();

    // Self-protection: the administrator cannot delete its own account.
    await page.goto(`/en/admin/users?q=${encodeURIComponent(adminEmail)}`);
    await accountRow(page, adminEmail).getByRole("link", { name: /^edit$/i }).click();
    await expect(page.locator("#admin-account-confirm-delete")).toHaveCount(0);

    // Delete a created account after accepting the confirmation dialog.
    await page.goto(`/en/admin/users?q=${encodeURIComponent(updated)}`);
    await accountRow(page, updated).getByRole("link", { name: /^edit$/i }).click();
    page.once("dialog", (dialog) => dialog.accept());
    await page.locator("#admin-account-confirm-delete").check();
    await page.getByRole("button", { name: /delete account/i }).click();
    await expect(page).toHaveURL(/\/en\/admin\/users$/);
    await page.goto(`/en/admin/users?q=${encodeURIComponent(updated)}`);
    await expect(page.getByText(/no accounts match/i)).toBeVisible();
  });

  test("sections render as labelled tabs and account filters are labelled", async ({ page }) => {
    await signInAdmin(page);
    await page.goto("/en/admin/users");

    const sections = page.getByRole("tablist", { name: /sections/i });
    await expect(sections).toBeVisible();
    await expect(page.getByRole("tab", { name: /^accounts$/i })).toHaveAttribute("aria-current", "page");

    for (const name of ["Administrator", "Guest", "Confirmed"]) {
      await expect(page.getByRole("group", { name })).toBeVisible();
    }

    await page.getByRole("tab", { name: /^audit log$/i }).click();
    await expect(page).toHaveURL(/\/en\/admin\/audit$/);
    await expect(page.getByRole("tab", { name: /^audit log$/i })).toHaveAttribute("aria-current", "page");
  });

  test("audit log lists recent administrator actions", async ({ page }) => {
    await signInAdmin(page);
    const email = uniqueEmail("admin-audit");
    await createAccount(page, email, uniquePassword());

    await page.goto("/en/admin/audit");
    await expect(page.getByRole("heading", { level: 1, name: /audit log/i })).toBeVisible();
    await expect(page.locator("tbody tr").first()).toBeVisible();

    await page.goto(`/en/admin/audit?action=account.created`);
    await expect(accountRow(page, "admin.account.created")).toBeVisible();
    await expect(page.locator("body")).not.toContainText(/password_hash|argon2/i);
  });
});
