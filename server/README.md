# carapace-server

Control-plane API: accounts, sessions, owner keys, the ciphertext store, API
keys, and the attested enclave API with its receipt log.

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
| `CARAPACE_ALLOWED_IMAGE_DIGESTS` | comma list of `sha256:<hex>` enclave images |
| `CARAPACE_ATTESTATION_PROJECT_ID` | GCP project the enclave VMs run in |
| `CARAPACE_ATTESTATION_SERVICE_ACCOUNT` | the enclave VMs' service account |

Optional, set together: `CARAPACE_KMS_PUBLIC_KEY_PEM` (RSA 3072-8192 SPKI
PEM) and `CARAPACE_KMS_KEY_VERSION` (the full
`projects/*/locations/*/keyRings/*/cryptoKeys/*/cryptoKeyVersions/N` name the
enclave reports; anything else is refused at startup). They are served at
`GET /v1/kms/public-key` for the CLI, which seals only if they equal the
KMS key the attested enclave reports. Without them `carapace verify` fails.

Optional: `CARAPACE_WEB_DIR` points at a built web UI (`web/dist`), which is
then served at `/`, never under a path the API owns (`/v1`, `/healthz`), so
enabling it changes no API response. Only those static responses carry
the UI's security headers (a strict CSP with Trusted Types, `nosniff`,
`DENY` framing, `no-referrer`, COOP/CORP `same-origin`, a Permissions-Policy
and, for an https public URL, HSTS). Hashed `assets/*` are cached as
immutable and everything else is `no-cache`. There is no CORS.

Rate limits (and the address stored with a session) key on the client IP;
IPv6 clients are bucketed by /64. Behind a reverse proxy the client IP is
the proxy's address, so every caller shares one bucket and one client can
exhaust the login limits for everyone. Set `CARAPACE_TRUSTED_PROXY_HOPS`
to the number of `X-Forwarded-For` entries the proxies in front of the
server append (default `0`): each hop normally appends the address it
accepted the connection from, so the client is the entry that many from
the right. Entries to its left are client-supplied and ignored; a shorter
chain or a non-IP entry falls back to the peer address. Cloud Run's
frontend appends one, so the Pulumi stack sets `1`; a Google external load
balancer in front of it appends two more. Do not combine this with
uvicorn's `--proxy-headers`, and never use `--forwarded-allow-ips='*'`,
which takes the leftmost, client-supplied entry.

## Container image

`server/Dockerfile` builds the image Cloud Run runs; build it from the
repository root. Dependencies come from `requirements.lock`, the hash-locked
`uv export` of `uv.lock` for this package (a test fails if it drifts):

```bash
uv export --package carapace-server --no-dev --frozen --no-emit-workspace \
  --no-header --no-annotate --format requirements-txt -o server/requirements.lock
docker buildx build -f server/Dockerfile --platform linux/amd64 -t carapace-server .
```

A `web` build stage (a node image pinned by digest, like the others)
installs the UI's dependencies from `web/package-lock.json` with
`npm ci --ignore-scripts` and runs `npm run build`; only the resulting
`dist/` is copied into the final image, at `/app/web`, and the image sets
`CARAPACE_WEB_DIR` to it, so the service serves the UI at `/`.

The entrypoint, `python3 -m carapace_server`, serves on `$PORT` (default
8080) as uid 65532 and needs no writable path. Migrations run from the same
image with `python3 -m alembic -c /app/server/alembic.ini upgrade head`; the
Pulumi stack does this in a Cloud Run job (`infra/pulumi/README.md`). The
entrypoint starts uvicorn with its proxy-header handling off; the client
address behind a proxy comes only from `CARAPACE_TRUSTED_PROXY_HOPS` (above).

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
- Request bodies are capped (`CARAPACE_MAX_REQUEST_BODY_BYTES`, default
  2 MiB, 413 above it) before anything buffers or parses them, and
  validation errors (422) never echo the rejected input.

## Owner keys, secrets and API keys

Owners sign everything the enclave trusts with an Ed25519 **owner key**
whose seed stays on their device (`docs/design/owner-signing.md`). The
server stores signed objects and checks them as defense in depth; the
enclave repeats every check against the fingerprint in the agent's API key,
so a compromised server or database can deny service or replay older
owner-signed objects, but cannot forge one.

- `/v1/owner-keys` registers, lists and retires public keys. There is no
  proof of possession: a key whose seed you do not hold signs nothing. Keys
  must pass `validate_public_key` (small-order and non-canonical points are
  rejected, 422), are globally unique (409) and are capped at 10 per
  account, retired ones included (409).
- `/v1/secrets` stores owner-signed envelope v1 (`carapace_crypto.envelope`).
  The server parses it with `Envelope.from_dict`, verifies the signature
  with `verify_envelope_signature`, and requires `owner_pk` to be one of the
  caller's registered, non-retired keys (422 otherwise). It also requires
  canonical lowercase UUIDs (so the envelope it rebuilds from its columns is
  byte for byte the signed one), a policy of at most 16 KiB and a wrapped
  key of at most 512 bytes. Reads return the full signed envelope.
- The client picks the secret UUID because it is signed and bound into the
  AAD. The envelope's `secret_id` and `owner_id` must match the URL and the
  caller.
- There is no way to edit a policy on its own. `PATCH` accepts `name` and/or
  a complete new envelope with a strictly higher `version` (409 otherwise;
  the comparison is part of the `UPDATE`, so concurrent uploads cannot both
  win).
- `/v1/api-keys` never generates or sees a raw key. The owner's CLI mints
  `cpk_<fingerprint>_<random>`, signs a grant for it and registers
  `{name, lookup_hash, grant}`. The server stores the lookup hash and the
  grant verbatim, and checks the grant's signature, that it is signed by an
  active key of the caller, that every secret in it is the caller's, and
  that it is not expired or issued in the future (400 otherwise). It cannot
  check `key_bind`; the enclave does, from the raw key.
- `PUT /v1/api-keys/{id}/grant` replaces the grant with one for the same key
  (same `owner_pk` and `key_bind`) and a strictly higher `iat` (409
  otherwise). `POST /v1/api-keys/{id}/revoke` revokes, optionally storing a
  tombstone (a newer grant with no secrets) as the current grant. A
  tombstone may be signed by a retired owner key: the enclave does not know
  about retirement, so the tombstone is what stops the old grant early.
- `api_key_secrets` is an index derived from the stored grant, used for the
  owner's listing. `find_grant(lookup_hash)`, which the enclave API uses,
  returns the current grant of any known key, expired or out of scope
  included: the enclave decides from the signed grant and can only record a
  tombstone in its monotonic cache if it is served one. A revoked key is
  served only while its stored grant is a tombstone; a key revoked without
  one (the web UI cannot sign) is withheld, since its stored grant is still
  the live one and the enclave would honour it until `exp`.

## Enclave API (`/internal/*`)

Enclaves authenticate with a Confidential Space OIDC token whose audience is
`CARAPACE_PUBLIC_URL`. Google's signing keys are found via OIDC discovery and
cached for an hour (refetched early for an unknown `kid`, at most once a
minute). A token is accepted only with RS256, the right `iss`/`aud`, a live
`exp`, `swname=CONFIDENTIAL_SPACE`, an allowed `hwmodel`,
`dbgstat=disabled-since-boot`, `secboot=true`, `STABLE` support, an allowed
image digest, and the configured project and service account. These mirror
the KMS key-release policy, so the server never trusts an enclave the KMS
would not.

`CARAPACE_ATTESTATION_ISSUER=mock://local` plus
`CARAPACE_MOCK_ATTESTATION_PUBLIC_KEY_PEM` enables a local mock enclave. Both
config and the verifier refuse it outside `dev`.

| Endpoint | Purpose |
| --- | --- |
| `POST /internal/boots` | register `{receipt_pubkey, tls_cert_pem}`; `eat_nonce` must equal `sha256(tls_spki_der ‖ receipt_pubkey)` |
| `GET /internal/secrets/{id}` | the full owner-signed envelope (`owner_pk`, `version`, `sig` included) |
| `POST /internal/keys/verify` | `{key_hash, secret_id}` → `{grant}`, or 404 for an unknown key or one revoked without a tombstone |
| `POST /internal/receipts` | append a batch of signed receipts |

`key_hash` is hex of the API key's `lookup_hash`. `keys/verify` returns the
key's current owner-signed grant for every known key, including revoked
keys whose grant is a tombstone, expired grants and grants that do not
cover `secret_id`, which is only logged. A key revoked without a tombstone
(the web UI cannot sign one) gets 404: its stored grant is still the live
one, which the enclave would honour until `exp`.
There is no `{allowed}` boolean: an answer from the server is not evidence.
The enclave verifies the grant against the raw key
(`carapace_crypto.verify_grant`), records it in its per-boot monotonic
cache, and only then checks scope and version floor
(`docs/design/owner-signing.md`).

All but the first require a registered boot (403 otherwise) and a request
signature from its receipt key (401 otherwise). Owners can read boots'
attestation tokens from `/v1/receipts`, so a token alone must not unlock
anything:

```
message = "carapace-internal-v1\n" METHOD "\n" PATH[?QUERY] "\n"
          TIMESTAMP "\n" hex(sha256(body))
X-Carapace-Timestamp: unix seconds (±60 s)
X-Carapace-Signature: base64(Ed25519(receipt_key, message))
```

### Receipts

Each boot keeps one hash chain, signed with the Ed25519 key it registered:

```
signed = canonical_json({"boot_id", "seq", "prev_hash", "payload"})
hash   = sha256(signed).hex()
sig    = Ed25519(receipt_key, signed)     # base64, 64 bytes
```

`boot_id` is the boot's `eat_nonce` (hex). The first receipt has `seq` 0 and
`prev_hash` of 64 zeros. Ingest checks the signature and continuity of every
receipt and stores the batch atomically; unsigned receipts, gaps and forks
are rejected. Re-sending an already stored receipt is a no-op, so retries
are safe.

`GET /v1/receipts?secret_id=&cursor=&limit=` returns an owner's receipts
verbatim, with the boots (attestation token, TLS cert, receipt key) needed to
verify them offline. `GET /v1/receipts/boots` lists the boots that signed at
least one of the caller's receipts, newest first, for the web UI's
attestation page. A receipt belongs to the signed `payload.owner_id`,
which the enclave reads from the AAD-bound envelope; this stays correct
after the secret is deleted, or its id re-created by another account. Only
a receipt without `owner_id` falls back to the current owner of
`payload.secret_id`. Payloads are capped at 16 KiB of canonical JSON
(`carapace_crypto.canonical_json`: no floats, no lone surrogates, integers
within ±2^53).

Payloads are produced by the enclave and stored verbatim; the server indexes
only `secret_id` and `owner_id`. Alongside them the enclave records which
owner-signed objects authorized the request, so `carapace audit verify` can
show which grant and which version of a secret each request used:

| Field | Meaning |
| --- | --- |
| `owner_id`, `secret_id` | from the verified envelope |
| `owner_fp` | hex `fingerprint(grant.owner_pk)`, the owner key that signed both |
| `envelope_version` | `version` of the envelope that was decrypted |
| `grant_iat` | `iat` of the grant that authorized the key |

## Known limitations

- Registering an existing email returns 400, which reveals the account
  exists. Closing this requires email verification, which is out of scope.
- In-process rate limits are per replica.
- A captured signed `/internal` request can be replayed within its 60 s
  window. This requires breaking TLS to the server; there is no nonce store.
- A boot's chain holds every owner's receipts, so an owner sees `seq` gaps
  and cannot prove on their own that nothing was withheld between them.
