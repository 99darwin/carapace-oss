/// <reference types="vitest/config" />
import react from "@vitejs/plugin-react";
import { defineConfig } from "vite";

// The server that `npm run dev` proxies API calls to. Same-origin in
// production, so the server needs no CORS.
const API_TARGET = process.env["CARAPACE_API"] ?? "http://127.0.0.1:8000";

export default defineConfig({
  plugins: [react()],
  build: {
    // No inline data: URIs; the CSP allows only same-origin assets.
    assetsInlineLimit: 0,
    sourcemap: false,
  },
  server: {
    proxy: { "/v1": API_TARGET, "/healthz": API_TARGET },
  },
  test: {
    environment: "jsdom",
    include: ["src/**/*.test.{ts,tsx}"],
    restoreMocks: true,
  },
});
