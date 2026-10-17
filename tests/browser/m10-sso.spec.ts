import { expect, test, type Browser, type BrowserContext, type Page } from "@playwright/test";

// Single sign-on across a provider app, a client app, and Hydra.
//
// Opt-in: GOWEB_SSO_E2E=1 with the three processes running (see
// docs/local-development.md: make sso-up, sso-client, run-provider,
// run-client). Provider and client must be on different host names because
// cookies ignore ports; the defaults match the documented loopback setup.
const enabled = process.env.GOWEB_SSO_E2E === "1";
const providerURL = (process.env.GOWEB_BROWSER_SSO_PROVIDER_URL ?? process.env.SSO_DEV_PROVIDER_URL ?? "http://localhost:8080").replace(/\/$/, "");
const clientURL = (process.env.GOWEB_BROWSER_SSO_CLIENT_URL ?? process.env.SSO_DEV_CLIENT_URL ?? "http://127.0.0.1:8081").replace(/\/$/, "");
// Mail for the password-reset scenario: the provider must send through
// Mailpit (GOWEB_MAIL_RELAY=smtp://localhost:1025) and this is its web API.
const mailpitURL = (process.env.GOWEB_BROWSER_SSO_MAILPIT_URL ?? "").replace(/\/$/, "");
// The name scripts/hydra-dev-client.sh registers for the development client.
const clientName = process.env.GOWEB_BROWSER_SSO_CLIENT_NAME ?? "goweb development client";
const adminEmail = process.env.GOWEB_BOOTSTRAP_ADMIN_EMAIL ?? "";
const adminPassword = process.env.GOWEB_BOOTSTRAP_ADMIN_PASSWORD ?? "";

const invitePattern = /^[A-HJKMNPQRSTUVWXYZ2-9]{12}$/;

function uniqueEmail(prefix: string): string {
  return `${prefix}-${crypto.randomUUID()}@example.test`;
}

function uniquePassword(): string {
  return `sso-${crypto.randomUUID()}-password`;
}

// The provider's sign-in and sign-up forms redirect straight back to Hydra
// when a login challenge is pending, so signing up here finishes the flow.
async function signUpAtProvider(page: Page, email: string, password: string): Promise<void> {
  await page.goto(`${providerURL}/en/sign-up`);
  await expect(page.getByTestId("sso-client-name")).toContainText(clientName);
  await page.getByLabel("Email", { exact: true }).fill(email);
  await page.getByLabel("Password", { exact: true }).fill(password);
  await page.getByRole("button", { name: /create account/i }).click();
}

async function signInAtProvider(page: Page, identifier: string, password: string): Promise<void> {
  await page.getByLabel("Email or username", { exact: true }).fill(identifier);
  await page.getByLabel("Password", { exact: true }).fill(password);
  await page.getByRole("button", { name: /^sign in$/i }).click();
}

async function startClientSignIn(page: Page): Promise<void> {
  await page.goto(`${clientURL}/en/sign-in`);
  await page.getByTestId("sso-sign-in").click();
}

// A brand-new person opens the client, is sent to the provider, signs up
// there, and lands on the client home signed in.
async function newClientUser(browser: Browser): Promise<{ context: BrowserContext; page: Page; email: string; password: string }> {
  const context = await browser.newContext();
  const page = await context.newPage();
  const email = uniqueEmail("sso");
  const password = uniquePassword();
  await startClientSignIn(page);
  await expect(page).toHaveURL(`${providerURL}/en/sign-in`);
  // The provider says which app the visitor is signing in to.
  await expect(page.getByTestId("sso-client-name")).toContainText(clientName);
  await signUpAtProvider(page, email, password);
  await expect(page).toHaveURL(`${clientURL}/en/home`);
  return { context, page, email, password };
}

async function expectClientSignedOut(page: Page): Promise<void> {
  // Back-channel logout is asynchronous, so poll the client until it asks for
  // a sign-in.
  await expect
    .poll(
      async () => {
        await page.goto(`${clientURL}/en/home`);
        return new URL(page.url()).pathname;
      },
      { timeout: 20_000, intervals: [500, 1000, 2000] },
    )
    .toBe("/en/sign-in");
}

async function adminContext(browser: Browser): Promise<{ context: BrowserContext; page: Page }> {
  const context = await browser.newContext();
  const page = await context.newPage();
  await page.goto(`${providerURL}/en/sign-in`);
  await signInAtProvider(page, adminEmail, adminPassword);
  await expect(page.getByRole("heading", { level: 1, name: /your home/i })).toBeVisible();
  return { context, page };
}

async function readResetLink(email: string): Promise<string> {
  let link = "";
  await expect
    .poll(
      async () => {
        const search = await fetch(`${mailpitURL}/api/v1/search?query=${encodeURIComponent(`to:${email}`)}`);
        const found = (await search.json()) as { messages?: { ID: string }[] };
        const id = found.messages?.[0]?.ID;
        if (!id) return "";
        const message = (await (await fetch(`${mailpitURL}/api/v1/message/${id}`)).json()) as { Text?: string };
        link = message.Text?.match(/https?:\/\/\S+\/reset-password\?token=\S+/)?.[0] ?? "";
        return link;
      },
      { timeout: 15_000, intervals: [250, 500, 1000] },
    )
    .not.toBe("");
  return link;
}

test.describe("M10 single sign-on", () => {
  test.skip(!enabled, "set GOWEB_SSO_E2E=1 to run the single sign-on specs");
  // Sign-in and sign-up are rate limited per origin, and the scenarios share
  // Hydra, so run them one after another.
  test.describe.configure({ mode: "serial" });

  test("first visit signs in through the provider and returns to the client", async ({ browser }) => {
    const { context, page, email } = await newClientUser(browser);
    await expect(page.getByRole("heading", { level: 1, name: /your home/i })).toBeVisible();

    // The client keeps no credentials: settings show the provider's account.
    await page.goto(`${clientURL}/en/account/settings`);
    await expect(page.getByTestId("sso-account-email")).toHaveText(email);
    await expect(page.locator("#password-heading")).toHaveCount(0);

    // The same browser is signed in at the provider too.
    await page.goto(`${providerURL}/en/home`);
    await expect(page.getByRole("heading", { level: 1, name: /your home/i })).toBeVisible();
    await context.close();
  });

  test("a second client visit is silent", async ({ browser }) => {
    const { context, page } = await newClientUser(browser);
    // Forget the client session only; the provider and Hydra sessions stay.
    await context.clearCookies({ domain: new URL(clientURL).hostname });

    const providerHost = new URL(providerURL).host;
    const visited: string[] = [];
    page.on("framenavigated", (frame) => {
      if (frame === page.mainFrame()) visited.push(new URL(frame.url()).host + new URL(frame.url()).pathname);
    });
    await startClientSignIn(page);
    await expect(page).toHaveURL(`${clientURL}/en/home`);
    // Hydra and the provider's /sso/* routes only redirect, so the browser
    // never commits a provider page; the sign-in form must not be among them.
    expect(visited).not.toContain(`${providerHost}/en/sign-in`);
    await context.close();
  });

  test("signing out of the client also ends the provider session", async ({ browser }) => {
    const { context, page } = await newClientUser(browser);
    await page.locator("summary[aria-label='Account menu']").click();
    await page.getByRole("button", { name: /sign out/i }).click();
    await expect(page).toHaveURL(`${clientURL}/en/sign-in`);

    await page.goto(`${providerURL}/en/home`);
    await expect(page).toHaveURL(`${providerURL}/en/sign-in`);
    // Hydra's session ended too: the next client sign-in needs credentials.
    await startClientSignIn(page);
    await expect(page).toHaveURL(`${providerURL}/en/sign-in`);
    await context.close();
  });

  test("an administrator revoking sessions at the provider logs the client out", async ({ browser }) => {
    test.skip(!adminEmail || !adminPassword, "requires GOWEB_BOOTSTRAP_ADMIN_EMAIL and GOWEB_BOOTSTRAP_ADMIN_PASSWORD");
    const user = await newClientUser(browser);
    const admin = await adminContext(browser);

    await admin.page.goto(`${providerURL}/en/admin/users?q=${encodeURIComponent(user.email)}`);
    await admin.page.locator("tbody tr").filter({ hasText: user.email }).getByRole("link", { name: /view/i }).click();
    admin.page.once("dialog", (dialog) => void dialog.accept());
    await admin.page.locator("section[aria-labelledby=admin-sessions-heading] form button[type=submit]").click();
    await expect(admin.page.locator("[data-testid=session-count]")).toHaveText("0");

    await expectClientSignedOut(user.page);
    await admin.context.close();
    await user.context.close();
  });

  test("a password reset at the provider logs the client out", async ({ browser }) => {
    test.skip(!mailpitURL, "requires GOWEB_BROWSER_SSO_MAILPIT_URL and a provider sending through Mailpit");
    const user = await newClientUser(browser);

    // Another device requests and completes the reset.
    const other = await browser.newContext();
    const otherPage = await other.newPage();
    await otherPage.goto(`${providerURL}/en/forgot-password`);
    await otherPage.getByLabel("Email").fill(user.email);
    await otherPage.getByRole("button", { name: /send reset link/i }).click();
    await expect(otherPage.locator("#alerts")).toContainText(/instructions will arrive/i);
    const link = new URL(await readResetLink(user.email));
    await otherPage.goto(link.href);
    const newPassword = uniquePassword();
    await otherPage.getByLabel("New password", { exact: true }).fill(newPassword);
    await otherPage.getByRole("button", { name: /set new password/i }).click();
    await expect(otherPage.locator("#alerts")).toContainText(/password changed/i);

    await expectClientSignedOut(user.page);
    await other.close();
    await user.context.close();
  });

  test("a guest upgrade through single sign-on keeps the guest's groups", async ({ browser }) => {
    // A signed-in user creates a group and shares its invite code.
    const owner = await newClientUser(browser);
    await owner.page.goto(`${clientURL}/en/groups`);
    await owner.page.locator("#group-new-name").fill(`SSO ${crypto.randomUUID().slice(0, 8)}`);
    await owner.page.locator("#group-new-name").locator("xpath=ancestor::form").getByRole("button").click();
    await owner.page.waitForURL(/\/en\/groups\/\d+$/);
    const inviteCode = (await owner.page.getByTestId("group-invite-code").innerText()).trim();
    expect(inviteCode).toMatch(invitePattern);
    const groupName = await owner.page.locator("#group-summary-heading").innerText();

    // A guest joins it, then keeps the account by signing up at the provider.
    const guestContext = await browser.newContext();
    const guest = await guestContext.newPage();
    await guest.goto(`${clientURL}/en/guest/write`);
    await guest.getByRole("button", { name: /save/i }).first().click();
    await expect(guest.locator("[data-guest-banner]")).toBeVisible();
    await guest.goto(`${clientURL}/en/groups/join`);
    await guest.locator("#group-invite-code").fill(inviteCode);
    await guest.locator("#group-invite-code").locator("xpath=ancestor::form").getByRole("button").click();
    await guest.waitForURL(/\/en\/groups\/\d+$/);
    const groupURL = guest.url();

    await guest.goto(`${clientURL}/en/guest/upgrade`);
    await expect(guest.locator("input[type=password]")).toHaveCount(0);
    await guest.getByTestId("guest-upgrade-sso").click();
    await expect(guest).toHaveURL(`${providerURL}/en/sign-in`);
    await signUpAtProvider(guest, uniqueEmail("sso-guest"), uniquePassword());
    await expect(guest).toHaveURL(`${clientURL}/en/home`);

    // Same account, no longer a guest, still a member of the group.
    await expect(guest.locator("[data-guest-banner]")).toHaveCount(0);
    await guest.goto(`${clientURL}/en/groups`);
    await expect(guest.getByText(groupName)).toBeVisible();
    await guest.goto(groupURL);
    await expect(guest.locator("#group-summary-heading")).toHaveText(groupName);
    await guestContext.close();
    await owner.context.close();
  });
});
