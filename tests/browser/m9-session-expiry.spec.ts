import { expect, test, type Page } from "@playwright/test";

const enabled = process.env.GOWEB_BROWSER_E2E === "1";
const fixtureEnabled = enabled && Boolean(process.env.GOWEB_DATABASE_URL);
const baseURL = process.env.GOWEB_BROWSER_BASE_URL ?? "http://127.0.0.1:8080";
const adminEmail = process.env.GOWEB_BOOTSTRAP_ADMIN_EMAIL ?? "";
const adminPassword = process.env.GOWEB_BOOTSTRAP_ADMIN_PASSWORD ?? "";
const adminEnabled =
  fixtureEnabled && Boolean(adminEmail) && Boolean(adminPassword);

function uniqueEmail(prefix: string): string {
  return `${prefix}-${crypto.randomUUID()}@example.test`;
}

function uniquePassword(): string {
  return `expiry-${crypto.randomUUID()}-password`;
}

async function signIn(page: Page, email: string, password: string): Promise<void> {
  await page.goto("/en/sign-in");
  await page.getByLabel("Email or username", { exact: true }).fill(email);
  await page.getByLabel("Password", { exact: true }).fill(password);
  await page.getByRole("button", { name: /^sign in$/i }).click();
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
  await expect(page.locator("tbody tr").filter({ hasText: email }).first()).toBeVisible();
}

async function revokeSessions(page: Page, email: string): Promise<void> {
  await page.goto(`/en/admin/users?q=${encodeURIComponent(email)}`);
  await page
    .locator("tbody tr")
    .filter({ hasText: email })
    .first()
    .getByRole("link", { name: /^view$/i })
    .click();
  await expect(page.getByRole("heading", { level: 1, name: email })).toBeVisible();
  page.once("dialog", (dialog) => dialog.accept());
  await page.getByRole("button", { name: /end all sessions/i }).click();
  await expect(page.getByText(/all sessions ended\./i)).toBeVisible();
}

function profileSaveButton(page: Page) {
  return page
    .locator("section[aria-labelledby='profile-heading']")
    .getByRole("button", { name: /save/i });
}

test.describe("M9 session expiry recovery", () => {
  test.skip(!enabled, "set GOWEB_BROWSER_E2E=1 to run browser acceptance specs");
  test.skip(!adminEnabled, "requires database and bootstrap administrator fixture");

  test("revoked session recovers on the next full-page navigation", async ({ browser, page }) => {
    await signInAdmin(page);
    const email = uniqueEmail("expire-full");
    const password = uniquePassword();
    await createAccount(page, email, password);

    const memberContext = await browser.newContext();
    const member = await memberContext.newPage();
    try {
      await signIn(member, email, password);
      await member.goto("/en/account/settings");
      await expect(member.locator("#settings-username")).toBeVisible();

      await revokeSessions(page, email);

      // The open page still shows content; the next normal request must recover.
      await member.goto("/en/account/settings");
      await expect(member).toHaveURL(/\/en\/sign-in$/);
      await expect(member.getByRole("heading", { level: 1, name: /sign in/i })).toBeVisible();
      await expect(member.locator("body")).not.toContainText(/password_hash|session[_ -]?digest/i);
    } finally {
      await memberContext.close();
    }
  });

  test("revoked session recovers on an in-page HTMX request", async ({ browser, page }) => {
    await signInAdmin(page);
    const email = uniqueEmail("expire-htmx");
    const password = uniquePassword();
    await createAccount(page, email, password);

    const memberContext = await browser.newContext();
    const member = await memberContext.newPage();
    try {
      await signIn(member, email, password);
      await member.goto("/en/account/settings");
      await expect(member.locator("#settings-username")).toBeVisible();

      await revokeSessions(page, email);

      // Submitting the HTMX-backed profile form on the stale page must trigger a
      // full-page redirect rather than swapping a fragment or leaking an error.
      await profileSaveButton(member).click();
      await expect(member).toHaveURL(/\/en\/sign-in$/);
      await expect(member.getByRole("heading", { level: 1, name: /sign in/i })).toBeVisible();
    } finally {
      await memberContext.close();
    }
  });

  test("invalid or expired session credential recovers safely", async ({ browser, page }) => {
    await signInAdmin(page);
    const email = uniqueEmail("expire-invalid");
    const password = uniquePassword();
    await createAccount(page, email, password);

    const memberContext = await browser.newContext();
    const member = await memberContext.newPage();
    try {
      await signIn(member, email, password);
      await member.goto("/en/account/settings");
      await expect(member.locator("#settings-username")).toBeVisible();

      // Overwrite only the session credential with a value the server cannot
      // resolve, simulating an expired or rotated session while the page stays
      // open. The CSRF cookie stays intact so the mutation is otherwise valid.
      await memberContext.addCookies([
        {
          name: "goweb_session",
          value: `expired-${crypto.randomUUID()}`,
          url: baseURL,
        },
      ]);

      await profileSaveButton(member).click();
      await expect(member).toHaveURL(/\/en\/sign-in$/);
      await expect(member.getByRole("heading", { level: 1, name: /sign in/i })).toBeVisible();

      await page.goto("/en/home");
      await expect(page.getByRole("heading", { level: 1, name: /your home/i })).toBeVisible();
    } finally {
      await memberContext.close();
    }
  });
});
