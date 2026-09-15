import { expect, test, type BrowserContext, type Page } from "@playwright/test";

const enabled = process.env.GOWEB_BROWSER_E2E === "1";
const fixtureEnabled = enabled && Boolean(process.env.GOWEB_DATABASE_URL);

const invitePattern = /^[A-HJKMNPQRSTUVWXYZ2-9]{12}$/;

function uniqueEmail(): string {
  return `groups-${crypto.randomUUID()}@example.test`;
}

function uniquePassword(): string {
  return `groups-${crypto.randomUUID()}-password`;
}

async function signUp(page: Page, email: string, password: string): Promise<void> {
  await page.goto("/en/sign-up");
  await page.getByLabel("Email", { exact: true }).fill(email);
  await page.getByLabel("Password", { exact: true }).fill(password);
  await page.getByRole("button", { name: /create account/i }).click();
  await expect(page.getByRole("heading", { level: 1, name: /your home/i })).toBeVisible();
}

async function createGroup(page: Page, name: string): Promise<void> {
  await page.goto("/en/groups");
  await page.locator("#group-new-name").fill(name);
  await page.locator("#group-new-name").locator("xpath=ancestor::form").getByRole("button").click();
  await page.waitForURL(/\/en\/groups\/\d+$/);
}

async function joinWithCode(page: Page, code: string): Promise<void> {
  await page.goto("/en/groups/join");
  await page.locator("#group-invite-code").fill(code);
  await page.locator("#group-invite-code").locator("xpath=ancestor::form").getByRole("button").click();
  await page.waitForURL(/\/en\/groups\/\d+$/);
}

test.describe("M6 groups", () => {
  test.skip(!enabled, "set GOWEB_BROWSER_E2E=1 to run browser acceptance specs");

  test("invite code joins a second account as an ordinary member", async ({ browser, page }) => {
    test.skip(!fixtureEnabled, "requires configured database fixture");
    const groupName = `Team ${crypto.randomUUID().slice(0, 8)}`;
    await signUp(page, uniqueEmail(), uniquePassword());
    await createGroup(page, groupName);

    const invite = page.locator('[data-testid="group-invite-code"]');
    await expect(invite).toHaveText(invitePattern);
    const code = (await invite.textContent())?.trim();
    if (!code) {
      throw new Error("invite code not rendered for the group administrator");
    }

    const memberContext: BrowserContext = await browser.newContext();
    const memberPage = await memberContext.newPage();
    try {
      await signUp(memberPage, uniqueEmail(), uniquePassword());
      await joinWithCode(memberPage, code);
      await expect(memberPage.getByRole("heading", { level: 1 })).toContainText(groupName);
      await expect(memberPage.locator('[data-testid="group-invite-code"]')).toHaveCount(0);
      await expect(memberPage.locator("tbody tr")).toHaveCount(2);
    } finally {
      await memberContext.close();
    }
  });

  test("administrators change roles and protect the last administrator", async ({ browser, page }) => {
    test.skip(!fixtureEnabled, "requires configured database fixture");
    const groupName = `Roles ${crypto.randomUUID().slice(0, 8)}`;
    await signUp(page, uniqueEmail(), uniquePassword());
    await createGroup(page, groupName);

    const invite = page.locator('[data-testid="group-invite-code"]');
    await expect(invite).toHaveText(invitePattern);
    const code = (await invite.textContent())?.trim() ?? "";

    const memberContext = await browser.newContext();
    const memberPage = await memberContext.newPage();
    try {
      await signUp(memberPage, uniqueEmail(), uniquePassword());
      await joinWithCode(memberPage, code);

      await page.reload();
      await expect(page.locator("tbody tr")).toHaveCount(2);

      const memberRow = page.locator('tbody tr:not(:has-text("You"))').last();
      await memberRow.getByRole("button", { name: /promote/i }).click();
      await expect(page.locator('tbody tr:has-text("Administrator")')).toHaveCount(2);

      await page.reload();
      await memberPage.reload();
      const otherRow = memberPage.locator('tbody tr:not(:has-text("You"))').last();
      await otherRow.getByRole("button", { name: /demote/i }).click();
      await expect(memberPage.getByRole("status").first()).toContainText(/membership updated/i);

      await memberPage.reload();
      const ownRow = memberPage.locator('tbody tr:has-text("You")');
      await ownRow.getByRole("button", { name: /demote/i }).click();
      await expect(memberPage.getByRole("alert").first()).toContainText(/at least one administrator/i);
    } finally {
      await memberContext.close();
    }
  });

  test("voluntary leave refuses the last administrator", async ({ page }) => {
    test.skip(!fixtureEnabled, "requires configured database fixture");
    await signUp(page, uniqueEmail(), uniquePassword());
    await createGroup(page, `Solo ${crypto.randomUUID().slice(0, 8)}`);

    page.once("dialog", (dialog) => dialog.accept());
    await page.getByRole("button", { name: /leave group/i }).click();
    await expect(page.getByRole("alert").first()).toContainText(/at least one administrator/i);
    await expect(page).toHaveURL(/\/en\/groups\/\d+$/);
  });

  test("rotating the invite code invalidates the previous code", async ({ browser, page }) => {
    test.skip(!fixtureEnabled, "requires configured database fixture");
    await signUp(page, uniqueEmail(), uniquePassword());
    await createGroup(page, `Rotate ${crypto.randomUUID().slice(0, 8)}`);

    const invite = page.locator('[data-testid="group-invite-code"]');
    const oldCode = (await invite.textContent())?.trim() ?? "";
    await page.getByRole("button", { name: /generate new code/i }).click();
    await expect(invite).not.toHaveText(oldCode);
    const newCode = (await invite.textContent())?.trim() ?? "";
    expect(newCode).toMatch(invitePattern);

    const memberContext = await browser.newContext();
    const memberPage = await memberContext.newPage();
    try {
      await signUp(memberPage, uniqueEmail(), uniquePassword());
      await memberPage.goto("/en/groups/join");
      await memberPage.locator("#group-invite-code").fill(oldCode);
      await memberPage.locator("#group-invite-code").locator("xpath=ancestor::form").getByRole("button").click();
      await expect(memberPage.getByRole("alert").first()).toContainText(/invalid or no longer available/i);
      expect(memberPage.url()).toContain("/en/groups");
    } finally {
      await memberContext.close();
    }
  });

  test("group pages never expose credentials", async ({ page }) => {
    test.skip(!fixtureEnabled, "requires configured database fixture");
    await signUp(page, uniqueEmail(), uniquePassword());
    await createGroup(page, `Safe ${crypto.randomUUID().slice(0, 8)}`);
    await expect(page.locator("body")).not.toContainText(/password_hash|session[_ -]?id|argon2|invite_code=/i);
  });
});
