import { expect, test, type BrowserContext, type Page } from "@playwright/test";

const enabled = process.env.GOWEB_BROWSER_E2E === "1";
const fixtureEnabled = enabled && Boolean(process.env.GOWEB_DATABASE_URL);
const adminEmail = process.env.GOWEB_BOOTSTRAP_ADMIN_EMAIL ?? "";
const adminPassword = process.env.GOWEB_BOOTSTRAP_ADMIN_PASSWORD ?? "";
const adminEnabled =
  fixtureEnabled && Boolean(adminEmail) && Boolean(adminPassword);

const guestWritePath = process.env.GOWEB_BROWSER_GUEST_WRITE_PATH ?? "/en/guest/write";
const guestTransferPath = process.env.GOWEB_BROWSER_GUEST_TRANSFER_PATH ?? "/en/guest/transfer";
const guestUpgradePath = process.env.GOWEB_BROWSER_GUEST_UPGRADE_PATH ?? "/en/guest/upgrade";

function uniqueEmail(prefix: string): string {
  return `${prefix}-${crypto.randomUUID()}@example.test`;
}

function uniquePassword(): string {
  return `golden-${crypto.randomUUID()}-password`;
}

async function signUp(page: Page, email: string, password: string): Promise<void> {
  await page.goto("/en/sign-up");
  await page.getByLabel("Email", { exact: true }).fill(email);
  await page.getByLabel("Password", { exact: true }).fill(password);
  await page.getByRole("button", { name: /create account/i }).click();
  await expect(page.getByRole("heading", { level: 1, name: /your home/i })).toBeVisible();
}

async function signIn(page: Page, email: string, password: string): Promise<void> {
  await page.goto("/en/sign-in");
  await page.getByLabel("Email or username", { exact: true }).fill(email);
  await page.getByLabel("Password", { exact: true }).fill(password);
  await page.getByRole("button", { name: /^sign in$/i }).click();
  await expect(page.getByRole("heading", { level: 1, name: /your home/i })).toBeVisible();
}

async function signInAdmin(page: Page): Promise<void> {
  await signIn(page, adminEmail, adminPassword);
}

async function signOut(page: Page): Promise<void> {
  await page.locator("summary[aria-label='Account menu']").click();
  await page.getByRole("button", { name: /sign out/i }).click();
  await expect(page).toHaveURL(/\/en\/sign-in$/);
}

function accountRow(page: Page, text: string) {
  return page.locator("tbody tr").filter({ hasText: text }).first();
}

async function createAccount(page: Page, email: string, password: string): Promise<void> {
  await page.goto("/en/admin/users/new");
  await page.locator("#admin-account-email").fill(email);
  await page.locator("#admin-account-password").fill(password);
  await page.getByRole("button", { name: /^create account$/i }).click();
  await expect(page).toHaveURL(/\/en\/admin\/users$/);
  await expect(accountRow(page, email)).toBeVisible();
}

test.describe("M9 golden path", () => {
  test.skip(!enabled, "set GOWEB_BROWSER_E2E=1 to run browser acceptance specs");

  test("member and administrator journey: sign-up through audit-preserving deletion", async ({ page }) => {
    test.skip(!adminEnabled, "requires database and bootstrap administrator fixture");

    // Public entry resolves to a localized document.
    await page.goto("/");
    await expect(page).toHaveURL(/\/en\/$/);
    await expect(page.locator("html")).toHaveAttribute("lang", "en");

    // Sign up, then refresh the session and persist an account theme.
    const memberEmail = uniqueEmail("golden-member");
    const memberPassword = uniquePassword();
    await signUp(page, memberEmail, memberPassword);
    await page.reload();
    await expect(page.getByRole("heading", { level: 1, name: /your home/i })).toBeVisible();

    await page.goto("/en/account/settings");
    const themeResponse = page.waitForResponse((response) => response.url().endsWith("/en/account/theme"));
    await page.locator('label[title="Toggle theme"]').click();
    expect((await themeResponse).status()).toBe(204);
    await page.reload();
    await expect(page.locator("html")).toHaveAttribute("data-account-theme", "dark");

    // Sign out, sign in again, and confirm non-administrators are denied.
    await signOut(page);
    await signIn(page, memberEmail, memberPassword);
    await page.goto("/en/admin");
    await expect(page.getByRole("heading", { level: 1, name: /access denied/i })).toBeVisible();

    // Administrator sign-in (return to a page that renders the account menu).
    await page.goto("/en/home");
    await signOut(page);
    await signInAdmin(page);
    await expect(page.getByRole("heading", { level: 1, name: /your home/i })).toBeVisible();

    // Create an account and confirm list state narrows to it.
    const targetEmail = uniqueEmail("golden-target");
    await createAccount(page, targetEmail, uniquePassword());
    await page.goto(`/en/admin/users?q=${encodeURIComponent(targetEmail)}`);
    await expect(page.locator("tbody tr[data-account-id]")).toHaveCount(1);

    // Account diagnostics expose safe live state.
    await accountRow(page, targetEmail).getByRole("link", { name: /^view$/i }).click();
    await expect(page.getByRole("heading", { level: 1, name: targetEmail })).toBeVisible();
    await expect(page.getByRole("heading", { name: /active sessions/i })).toBeVisible();
    await expect(page.getByRole("heading", { name: /recent sign-in attempts/i })).toBeVisible();
    await expect(page.getByRole("heading", { name: /linked providers/i })).toBeVisible();
    await expect(page.getByRole("heading", { name: /lockout/i })).toBeVisible();

    // System overview stays credential-free.
    await page.goto("/en/admin/system");
    await expect(page.getByRole("heading", { level: 1, name: /^system$/i })).toBeVisible();
    await expect(page.getByRole("heading", { name: /configuration/i })).toBeVisible();
    await expect(page.getByRole("heading", { name: /runtime/i })).toBeVisible();
    await expect(page.getByRole("heading", { name: /migrations/i })).toBeVisible();
    await expect(page.locator("body")).not.toContainText(
      /password_hash|session[_ -]?digest|postgres:\/\/|GOWEB_SESSION_SECRET/i,
    );

    // The create action is recorded in the audit log.
    await page.goto("/en/admin/audit?action=admin.account.created");
    await expect(accountRow(page, "admin.account.created")).toBeVisible();

    // Delete the account with an explicit confirmation.
    await page.goto(`/en/admin/users?q=${encodeURIComponent(targetEmail)}`);
    await accountRow(page, targetEmail).getByRole("link", { name: /^edit$/i }).click();
    await expect(page.locator("#admin-account-email")).toHaveValue(targetEmail);
    page.once("dialog", (dialog) => dialog.accept());
    await page.locator("#admin-account-confirm-delete").check();
    await page.getByRole("button", { name: /^delete account$/i }).click();
    await expect(page).toHaveURL(/\/en\/admin\/users$/);

    // The account is gone but its deletion remains in the audit log.
    await page.goto(`/en/admin/users?q=${encodeURIComponent(targetEmail)}`);
    await expect(page.getByText(/no accounts match/i)).toBeVisible();
    await page.goto("/en/admin/audit?action=admin.account.deleted");
    await expect(accountRow(page, "admin.account.deleted")).toBeVisible();
  });

  test("guest journey: create, transfer, upgrade, and sign in", async ({ browser, page }) => {
    test.skip(!fixtureEnabled, "requires configured database fixture");

    await page.goto(guestWritePath);
    await page.getByRole("button", { name: /save|create|add/i }).first().click();
    await expect(page.locator("[data-guest-banner]")).toBeVisible();
    await expect(page.locator("[data-guest-owned-state]")).toBeVisible();

    await page.goto(guestTransferPath);
    await page.getByRole("button", { name: /request|show|transfer/i }).click();
    const codeLocator = page.locator('[data-testid="guest-transfer-code"]');
    await expect(codeLocator).toHaveText(/^[A-HJKMNPQRSTUVWXYZ2-9]{10}$/);
    const transferCode = (await codeLocator.textContent())?.trim() ?? "";

    // A second browser redeems the transfer code and sees the same account.
    const browserInstance = browser;
    const secondContext: BrowserContext = await browserInstance.newContext();
    const secondPage = await secondContext.newPage();
    try {
      await secondPage.goto(guestTransferPath);
      await secondPage.getByLabel(/transfer code/i).fill(transferCode);
      await secondPage.getByRole("button", { name: /redeem|continue|sign in/i }).click();
      await expect(secondPage.locator("[data-guest-banner]")).toBeVisible();
      await expect(secondPage.locator("[data-guest-owned-state]")).toBeVisible();
    } finally {
      await secondContext.close();
    }

    // Upgrade the guest to a password account and sign in with it.
    const email = uniqueEmail("golden-guest");
    const password = uniquePassword();
    await page.goto(guestUpgradePath);
    await page.getByLabel("Email").fill(email);
    await page.getByLabel("Password", { exact: true }).fill(password);
    await page.getByRole("button", { name: /upgrade|create account|save/i }).click();
    await expect(page.locator("[data-guest-banner]")).toHaveCount(0);
    await expect(page.locator("[data-guest-owned-state]")).toBeVisible();

    await signOut(page);
    await signIn(page, email, password);
    await page.goto(guestWritePath);
    await expect(page.getByRole("heading", { level: 1 })).toBeVisible();
    await expect(page.locator("[data-guest-banner]")).toHaveCount(0);
    await expect(page.locator("body")).not.toContainText(/password_hash|session[_ -]?id/i);
  });

  test("group journey: create, rotate invite, view members, and leave", async ({ page }) => {
    test.skip(!fixtureEnabled, "requires configured database fixture");

    await signUp(page, uniqueEmail("golden-group"), uniquePassword());
    const groupName = `Golden ${crypto.randomUUID().slice(0, 8)}`;
    await page.goto("/en/groups");
    await page.locator("#group-new-name").fill(groupName);
    await page.locator("#group-new-name").locator("xpath=ancestor::form").getByRole("button").click();
    await page.waitForURL(/\/en\/groups\/\d+$/);
    await expect(page.getByRole("heading", { level: 1 })).toContainText(groupName);

    const invite = page.locator('[data-testid="group-invite-code"]');
    await expect(invite).toHaveText(/^[A-HJKMNPQRSTUVWXYZ2-9]{12}$/);
    const firstCode = (await invite.textContent())?.trim() ?? "";

    await page.getByRole("button", { name: /generate new code/i }).click();
    await expect(page.getByText(/new invite code was generated/i).first()).toBeVisible();
    const rotatedCode = (await invite.textContent())?.trim() ?? "";
    expect(rotatedCode).not.toBe(firstCode);

    await expect(page.locator("tbody tr")).toHaveCount(1);

    // The creator is the only administrator, so leaving must be refused.
    page.once("dialog", (dialog) => dialog.accept());
    await page.getByRole("button", { name: /leave group/i }).click();
    await expect(page.getByText(/must keep at least one administrator/i).first()).toBeVisible();
    await expect(page).toHaveURL(/\/en\/groups\/\d+$/);
  });

  test("locale journey: switch language and keep the settings path", async ({ page }) => {
    test.skip(!fixtureEnabled, "requires configured database fixture");

    await signUp(page, uniqueEmail("golden-locale"), uniquePassword());
    await page.goto("/en/account/settings");
    await page.getByLabel("Language", { exact: true }).selectOption("hu");
    await page.getByRole("button", { name: /^save$/i }).last().click();

    // The current page is preserved under the new language prefix.
    await page.waitForURL("**/hu/account/settings");
    await expect(page.locator("html")).toHaveAttribute("lang", "hu");
    await page.reload();
    await expect(page).toHaveURL(/\/hu\/account\/settings$/);
  });
});
