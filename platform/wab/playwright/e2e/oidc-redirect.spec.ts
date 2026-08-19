import { expect } from "playwright/test";
import { test } from "../fixtures/test";

test.describe("OIDC redirect", () => {
  test.beforeEach(async ({ page }) => {
    await page.context().clearCookies();
  });

  test("login page shows OIDC button and redirects to IdP", async ({
    page,
  }) => {
    await page.goto("/login");

    const oidcButton = page.locator("button", {
      hasText: "Sign in with OIDC",
    });
    await expect(oidcButton).toBeVisible();

    await oidcButton.click();

    // Wait for the browser to navigate away from the local app.
    await page.waitForURL(/auth\.sunbeam\.pt/, { timeout: 15_000 });

    // Confirm we reached the Ory login page rather than an error page.
    const csrfError = page.locator("text=No CSRF value available");
    await expect(csrfError).toHaveCount(0);

    // Take a screenshot of the IdP login page for manual verification.
    await page.screenshot({ path: "test-results/oidc-redirect.png" });
  });
});
