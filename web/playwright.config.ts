import { defineConfig, devices } from "@playwright/test";

const PORT = Number(process.env["E2E_PORT"] ?? "8765");

export default defineConfig({
  testDir: "e2e",
  forbidOnly: Boolean(process.env["CI"]),
  reporter: "list",
  use: { baseURL: `http://127.0.0.1:${String(PORT)}` },
  projects: [{ name: "chromium", use: { ...devices["Desktop Chrome"] } }],
  webServer: {
    command: "./e2e/serve.sh",
    url: `http://127.0.0.1:${String(PORT)}/healthz`,
    env: { E2E_PORT: String(PORT) },
    timeout: 120_000,
    reuseExistingServer: false,
  },
});
