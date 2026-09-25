import { expect, test } from "@playwright/test";

// Must match web/e2e/seed.py.
const EMAIL = "e2e@example.com";
const PASSWORD = "Correct-Horse-9-Battery";

test("log in, browse every page and revoke a key", async ({ page }) => {
  const problems: string[] = [];
  page.on("console", (message) => {
    if (message.type() === "error") problems.push(message.text());
  });
  page.on("pageerror", (error) => problems.push(error.message));

  const response = await page.goto("/");
  const csp = response?.headers()["content-security-policy"] ?? "";
  expect(csp).toContain("require-trusted-types-for 'script'");

  await page.getByLabel("Email").fill(EMAIL);
  await page.getByLabel("Password").fill(PASSWORD);
  await page.getByRole("button", { name: "Log in" }).click();

  await expect(page.getByRole("cell", { name: /^github/ })).toBeVisible();
  await expect(page.getByText("api.github.com")).toBeVisible();
  await expect(page.getByText(EMAIL)).toBeVisible();

  await page.getByRole("link", { name: "API keys" }).click();
  await expect(page.getByRole("note")).toContainText("carapace key revoke");
  await page.getByRole("button", { name: "Revoke" }).click();
  await page
    .getByRole("button", { name: "Confirm revoke of ci-agent" })
    .click();
  await expect(page.getByRole("status")).toContainText("Revoked ci-agent");
  await expect(page.getByText(/No API keys yet/)).toBeVisible();

  await page.getByRole("link", { name: "Receipts" }).click();
  await expect(page.getByRole("row")).toHaveCount(4);

  await page.getByRole("link", { name: "Attestation" }).click();
  await expect(page.getByText("GCP_AMD_SEV", { exact: true })).toBeVisible();
  await expect(page.getByText(/unverified — verify with/)).toBeVisible();

  // A reload drops the in-memory session.
  await page.reload();
  await expect(page.getByRole("button", { name: "Log in" })).toBeVisible();

  expect(problems).toEqual([]);
});
