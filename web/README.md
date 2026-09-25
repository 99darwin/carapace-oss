# Carapace web UI

A small single-page app on the server's JSON API. It shows secrets, API keys,
receipts and the attestation claims of the enclave boots that signed them,
and can revoke an API key. It never handles a secret or the owner key.
Sealing, minting keys and signing grants happen in the CLI.

## Security model

- **Read-only plus revoke.** The browser cannot sign, so a revoke here only
  sets `revoked_at` on the server. An honest server enforces that right away.
  A malicious server can keep serving the last grant until it expires. The
  page says so, and repeats `docs/THREAT_MODEL.md` R2: `carapace key revoke`
  (an owner-signed tombstone) helps only partially, and the only hard cutoff
  is rotating the credential at its provider.
- **Tokens live in memory.** No cookies and no storage, so a reload logs you
  out. Refresh tokens are single use, so concurrent 401s share one refresh.
- **Nothing is verified in the browser.** Receipts and attestation claims
  are shown as the server stored them and labelled unverified. Use
  `carapace audit verify` and `carapace verify` to check them.
- **Strict CSP with Trusted Types.** Only same-origin scripts, styles and
  connections. `dangerouslySetInnerHTML`, `innerHTML` and web storage are
  banned by lint rules. The only runtime dependencies are `react` and
  `react-dom`.

## Develop

```bash
npm ci
npm run dev        # proxies /v1 to CARAPACE_API (default http://127.0.0.1:8000)
npm run lint && npm run typecheck && npm test && npm run build
```

To serve a build from the server, set `CARAPACE_WEB_DIR=web/dist`.

## Smoke test

`npm run e2e` runs Playwright against `e2e/serve.sh`. The script migrates a
throwaway SQLite database, seeds it with `e2e/seed.py` and starts uvicorn
serving `dist/`. Run `npm run build` first. `uv` and
`npx playwright install chromium` are also required.
