# carapace-server

Control-plane API: accounts, sessions and (in later PRs) the ciphertext store.

The server is **untrusted** by design. It never sees plaintext secrets, holds
no KMS decrypt rights, and is not on the agent-to-enclave data path.

## Run locally

```bash
uv sync --all-packages
export CARAPACE_MODE=dev
uv run --package carapace-server alembic -c server/alembic.ini upgrade head
uv run --package carapace-server uvicorn carapace_server.app:create_app --factory
```

`dev` mode uses a local SQLite file and a random per-process JWT secret.
The default mode is `prod`, which refuses to start unless these are set:

| Variable | Notes |
| --- | --- |
| `CARAPACE_DATABASE_URL` | `postgresql+asyncpg://...` (SQLite rejected) |
| `CARAPACE_PUBLIC_URL` | `https://...`; also the passkey RP origin |
| `CARAPACE_JWT_SECRET` | at least 32 characters |

Behind a reverse proxy, run uvicorn with `--proxy-headers` and
`--forwarded-allow-ips` set to the proxy address so rate limits key on the
real client IP. The app never reads `X-Forwarded-For` itself.

## Design notes

- **Email is stored in plaintext** with a unique index. The old design
  sealed it with KMS, which put KMS on the login path and made uniqueness
  checks awkward. An email address is not a credential, and the server is
  already treated as untrusted, so the confidentiality it bought was small.
- Passwords: bcrypt over base64(sha256(password)) to avoid the 72-byte limit.
- Passkeys: full attestation verification with `py_webauthn`; user
  verification is required on every ceremony (a user-presence-only assertion
  is rejected); login options for unknown accounts return a deterministic
  decoy credential ID.
- Access JWTs carry `jti`, `iss`, `aud`; logout blacklists the `jti` in the
  database. Refresh tokens are single use and rotated atomically. Every
  rotation stays in the family of the login that started it; presenting an
  already-rotated token is treated as theft and revokes the whole family.
  Revoked rows are kept until they expire so that reuse remains detectable.
- No Redis or Celery: rate limiting is in-process (per replica) and expired
  rows are purged by a periodic asyncio task.

## Known limitations

- Registering an existing email returns 400, which reveals the account
  exists. Closing this requires email verification, which is out of scope.
- In-process rate limits are per replica.
