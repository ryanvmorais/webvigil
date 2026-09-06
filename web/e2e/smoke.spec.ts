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
  await expect(page.getByRole("table")).toBeVisible();

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
