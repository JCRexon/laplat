import { test, expect } from "@playwright/test";
import { readFileSync } from "node:fs";

// The console OTP sender logs each code as a JSON line; pull the latest code for
// an address from authd's captured log. This is exactly how a developer reads
// the code in dev — the test just automates it.
function latestOtp(email: string): string {
  const log = readFileSync(process.env.E2E_AUTHD_LOG!, "utf8");
  const lines = log.split("\n").filter(Boolean);
  for (let i = lines.length - 1; i >= 0; i--) {
    try {
      const o = JSON.parse(lines[i]);
      if (o.code && o.dest === email) return String(o.code);
    } catch {
      // non-JSON line; skip
    }
  }
  throw new Error(`no OTP code logged for ${email}`);
}

// The differentiated funnel, exercised through the real UI and real backend:
// email-OTP sign-in, then the first assurance climb (none -> declared), then the
// catalog renders. This is the smoke that turns "the frontend compiles" into
// "the frontend works against authd".
test("sign in via email OTP, climb to declared, reach the catalog", async ({ page }) => {
  const email = `e2e+${Date.now()}@laplat.test`;

  // Sign in.
  await page.goto("/signin");
  await page.getByPlaceholder("you@example.com").fill(email);
  await page.getByRole("button", { name: "Send code" }).click();
  await expect(page.getByText(/Code sent to/)).toBeVisible();

  await page.getByPlaceholder("123456").fill(latestOtp(email));
  await page.getByRole("button", { name: /Verify/ }).click();

  // Landed on onboarding at the lowest tier.
  await expect(page).toHaveURL(/\/onboarding/);
  const badge = page.locator("header .badge");
  await expect(badge).toHaveText("Browsing");
  await expect(page.getByRole("button", { name: /18 or older/ })).toBeVisible();

  // Climb to declared; the topbar tier badge updates after the re-mint.
  await page.getByRole("button", { name: /18 or older/ }).click();
  await expect(badge).toHaveText("Declared (18+)");

  // Catalog renders for a signed-in user.
  await page.goto("/catalog");
  await expect(page.getByRole("heading", { name: "Classes" })).toBeVisible();
});
