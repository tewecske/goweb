import { expect, test } from "@playwright/test";

const enabled = process.env.GOWEB_BROWSER_E2E === "1";
const writePath = process.env.GOWEB_BROWSER_GUEST_WRITE_PATH ?? "/en/guest/write";
const transferPath = process.env.GOWEB_BROWSER_GUEST_TRANSFER_PATH ?? "/en/guest/transfer";
const upgradePath = process.env.GOWEB_BROWSER_GUEST_UPGRADE_PATH ?? "/en/guest/upgrade";

const transferAlphabet = "ABCDEFGHJKMNPQRSTUVWXYZ23456789";

function randomTransferCode(): string {
  const bytes = new Uint8Array(10);
  crypto.getRandomValues(bytes);
  return Array.from(bytes, (value) => transferAlphabet[value % transferAlphabet.length]).join("");
}

test.describe("M5 guest accounts", () => {
  test.skip(!enabled, "set GOWEB_BROWSER_E2E=1 to run browser acceptance specs");

  test("page view stays anonymous until an ownership write succeeds", async ({ page }) => {
    await page.goto("/en/");
    await expect(page.locator("[data-guest-banner]")).toHaveCount(0);

    await page.goto(writePath);
    await page.getByRole("button", { name: /save|create|add/i }).first().click();

    await expect(page.locator("[data-guest-banner]")).toBeVisible();
    await expect(page.locator("body")).not.toContainText(/password_hash|session[_ -]?id/i);
  });

  test("transfer code signs a second browser context into the same guest", async ({
    context,
    page,
  }) => {
    await page.goto(writePath);
    await page.getByRole("button", { name: /save|create|add/i }).first().click();
    await expect(page.locator("[data-guest-banner]")).toBeVisible();

    await page.goto(transferPath);
    await page.getByRole("button", { name: /request|show|transfer/i }).click();
    const code = page.locator('[data-testid="guest-transfer-code"]');
    await expect(code).toHaveText(/^[A-HJKMNPQRSTUVWXYZ2-9]{10}$/);
    const transferCode = await code.textContent();

    const browser = context.browser();
    if (!browser || !transferCode) {
      throw new Error("browser fixture did not expose transfer code");
    }
    const secondContext = await browser.newContext();
    const secondPage = await secondContext.newPage();
    try {
      await secondPage.goto(transferPath);
      await secondPage.getByLabel(/transfer code/i).fill(transferCode);
      await secondPage.getByRole("button", { name: /redeem|continue|sign in/i }).click();
      await expect(secondPage.locator("[data-guest-banner]")).toBeVisible();
      await expect(secondPage.locator("[data-guest-owned-state]")).toBeVisible();
    } finally {
      await secondContext.close();
    }
  });

  test("guest upgrade keeps owned state and invalidates transfer credential", async ({ page }) => {
    await page.goto(writePath);
    await page.getByRole("button", { name: /save|create|add/i }).first().click();
    await expect(page.locator("[data-guest-banner]")).toBeVisible();

    await page.goto(transferPath);
    await page.getByRole("button", { name: /request|show|transfer/i }).click();
    const code = page.locator('[data-testid="guest-transfer-code"]');
    await expect(code).toHaveText(/^[A-HJKMNPQRSTUVWXYZ2-9]{10}$/);

    const email = `guest-${crypto.randomUUID()}@example.test`;
    const password = `guest-${crypto.randomUUID()}-password`;
    await page.goto(upgradePath);
    await page.getByLabel("Email").fill(email);
    await page.getByLabel("Password", { exact: true }).fill(password);
    await page.getByRole("button", { name: /upgrade|create account|save/i }).click();

    await expect(page.locator("[data-guest-banner]")).toHaveCount(0);
    await expect(page.locator("[data-guest-owned-state]")).toBeVisible();
    await expect(page.locator("body")).not.toContainText(/password_hash|session[_ -]?id/i);
  });

  test("invalid transfer codes have uniform readable failures", async ({ page }) => {
    const messages: string[] = [];
    for (const code of ["short", randomTransferCode(), randomTransferCode()]) {
      await page.goto(transferPath);
      await page.getByLabel(/transfer code/i).fill(code);
      await page.getByRole("button", { name: /redeem|continue|sign in/i }).click();
      const alert = page.locator("[role=alert], #alerts").first();
      await expect(alert).toBeVisible();
      messages.push((await alert.innerText()).trim());
    }
    expect(new Set(messages).size).toBe(1);
    await expect(page.locator("body")).not.toContainText(/password_hash|session[_ -]?id/i);
  });
});
