import { readFileSync } from "node:fs";

import { expect, test } from "@playwright/test";

import { TARGETS } from "../playwright.config";

const USERNAME = "e2e-admin";
const PASSWORD = "e2e-password-1";
const NEW_PASSWORD = "e2e-password-2";

test("setup → login → scan → report → password → logout", async ({ page }) => {
  // First run: the app sends us to /setup.
  await page.goto("/");
  await expect(page).toHaveURL(/\/setup$/);
  await page.getByLabel("Username").fill(USERNAME);
  await page.getByLabel("Password", { exact: true }).fill(PASSWORD);
  await page.getByLabel("Confirm password").fill(PASSWORD);
  await page.getByRole("button", { name: "Create account" }).click();

  // Then to /login with a success notice.
  await expect(page).toHaveURL(/\/login/);
  await page.getByLabel("Username").fill(USERNAME);
  await page.getByLabel("Password", { exact: true }).fill(PASSWORD);
  await page.getByRole("button", { name: "Sign in" }).click();

  await expect(page).toHaveURL(/\/scans$/);

  // New passive scan of the local fixture app.
  await page.getByRole("link", { name: "New scan" }).first().click();
  await expect(page).toHaveURL(/\/scans\/new$/);
  await page.getByLabel("Target").fill(TARGETS.fixture);
  await page.getByRole("button", { name: "Start scan" }).click();

  // Land on the detail view and wait for it to finish.
  await expect(page).toHaveURL(/\/scans\/\d+$/);
  await expect(page.getByText("Completed")).toBeVisible({ timeout: 60_000 });

  // Findings are listed.
  await expect(page.getByRole("heading", { name: "Findings" })).toBeVisible();
  await expect(page.getByRole("table").first()).toBeVisible();

  // The dependency fingerprint pass detected the vulnerable jQuery the fixture ships (spec 004).
  await expect(page.getByRole("heading", { name: "Detected technologies" })).toBeVisible();
  await expect(page.getByRole("button", { name: /Vulnerable \(CVE-/ })).toBeVisible();

  // Download the JSON report and confirm it parses.
  await page.getByRole("button", { name: "Report", exact: true }).click();
  const [download] = await Promise.all([
    page.waitForEvent("download"),
    page.getByRole("menuitem", { name: "JSON" }).click(),
  ]);
  expect(download.suggestedFilename()).toMatch(/^webvigil-\d+\.json$/);
  const path = await download.path();
  const parsed = JSON.parse(readFileSync(path, "utf-8"));
  expect(parsed).toHaveProperty("findings");

  // The HTML report opened inline in its own tab (issue #163): it arrives with the sandbox policy
  // and nosniff, and still renders, because its inline <style> is the one thing the policy allows.
  const scanId = new URL(page.url()).pathname.split("/").pop();
  const reportTab = await page.context().newPage();
  const violations: string[] = [];
  reportTab.on("console", (message) => {
    if (/content security policy/i.test(message.text())) violations.push(message.text());
  });
  const reportResponse = await reportTab.goto(
    `/api/scans/${scanId}/report?format=html&download=false`,
  );
  expect(reportResponse?.headers()["x-content-type-options"]).toBe("nosniff");
  expect(reportResponse?.headers()["content-security-policy"]).toBe(
    "sandbox; default-src 'none'; style-src 'unsafe-inline'",
  );
  await expect(reportTab.getByRole("heading", { level: 1 })).toBeVisible();
  // The report sets `body { font: 15px ... }`; the browser default would be 16px.
  expect(await reportTab.evaluate(() => getComputedStyle(document.body).fontSize)).toBe("15px");
  expect(violations).toEqual([]);
  await reportTab.close();

  // Change the password.
  await page.goto("/settings");
  await page.getByLabel("Current password").fill(PASSWORD);
  await page.getByLabel("New password", { exact: true }).fill(NEW_PASSWORD);
  await page.getByLabel("Confirm new password").fill(NEW_PASSWORD);
  await page.getByRole("button", { name: "Change password" }).click();
  await expect(page.getByText("Password changed.")).toBeVisible();

  // Log out.
  await page
    .getByRole("button", { name: /log out/i })
    .first()
    .click();
  await expect(page).toHaveURL(/\/login$/);
});
