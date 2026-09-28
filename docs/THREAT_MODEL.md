# Threat model

This document describes what Carapace protects, who it defends against, what
it trusts, and which risks it knowingly leaves open. It describes the code on
`main`, not the roadmap. Where a guarantee depends on behaviour of Google
infrastructure that has not yet been checked on real hardware, it says so.

[SECURITY.md](../SECURITY.md) defines what counts as a vulnerability. In
short, a report is in scope if it lets any party other than the owner obtain a
secret's plaintext, use a secret outside its policy, forge or suppress
receipts, or make a non-attested workload decrypt. A report that only
restates one of the [residual risks](#residual-risks) below is out of scope,
unless it shows the risk is larger than described here.

Related documents: [ARCHITECTURE.md](ARCHITECTURE.md) (design),
[design/owner-signing.md](design/owner-signing.md) (owner signatures, grants,
freshness), [VERIFY.md](VERIFY.md) (checking an enclave and receipts),
[SELF_HOST.md](SELF_HOST.md) (deploying your own).

> **Status: beta.** Not independently audited; start with scoped, revocable
> tokens. The system has run end to end on real Confidential Space
> hardware twice: 2026-09-26, images built from source with `carapace
> deploy --build`; and 2026-09-28, deployed from a published, signed
> release with plain `carapace deploy`, including the web UI. See
> [Verified on real GCP](#verified-on-real-gcp) and [Unverified
> assumptions](#unverified-assumptions).

## Assets

| Asset | Where it lives | Why it matters |
|---|---|---|
| Secret plaintext (API tokens, passwords) | Owner's device at sealing time; enclave memory while serving a request | The thing being protected |
| Data encryption keys (DEKs) | Wrapped by the KMS key in each envelope; unwrapped only in enclave memory, cached ≤ 60 s | Unwrapping one yields the secret |
| KMS private key (RSA-4096, HSM) | Cloud KMS HSM; never exported | Decrypts every DEK |
| Owner signing key (Ed25519 seed) | Owner's device, `owner-key.json` (0600, optionally scrypt + AES-256-GCM under a passphrase) | Authorizes envelopes, policies and grants |
| Agent API keys (`cpk_…`) | Agent's environment or a 0600 file | Lets an agent use the secrets its grant names, within policy |
| Per-boot enclave keys (TLS P-256, receipt Ed25519) | Enclave memory only, regenerated every boot | Bind TLS sessions and receipts to an attested boot |
| Receipts and boot records | Server database | Audit trail of every authorized use |

## Actors

| Actor | Trusted? | Capabilities assumed |
|---|---|---|
| **Owner** | Yes, for their own secrets | Holds the owner seed; runs the CLI |
| **Agent** | No | Holds an API key; can send arbitrary requests to the enclave |
| **Server operator / database writer** | No | Full control of the control plane and its database: can read, write, withhold, replay and delete any stored object, mint API key records, and lie in any API response |
| **Anyone on the internet** | No | Can reach the server's public API, including `POST /v1/auth/register`; without an account they can do nothing else (see G13) |
| **Network attacker** | No | Can observe, drop, delay and modify traffic between any two parties |
| **VM host operator** | No | Controls the hypervisor, guest clock, disk and network of the enclave VM, but not its encrypted memory (AMD SEV) |
| **Other tenants** | No | Their own owner keys and API keys; can send traffic to the shared enclave |
| **GCP project Owner/Editor** | Partly: see [residual risks](#residual-risks) | An Owner can change IAM, including on the KMS key, and so grant itself decrypt. An Editor cannot change IAM and holds no KMS decrypt permission; it can reconfigure, stop or replace the enclave VM, which costs availability, not secrets. Self-hosters are their own project owner |
| **Upstream API** (the service a secret authenticates to) | No, beyond holding the secret legitimately | Sees the secret on every request, by design |

## Trusted computing base

A secret's confidentiality rests on the following components. A compromise
of any of them can expose plaintext.

1. **AMD SEV hardware and Google's Shielded VM firmware and vTPM.** The
   enclave runs as a Confidential VM with AMD SEV (the attestation token
   reports `hwmodel = GCP_AMD_SEV`), **not SEV-SNP**. SEV encrypts guest
   memory but does not provide SNP's integrity protection or a
   hardware-signed attestation report. The attestation is rooted in Google's
   vTPM and measured boot. Google is therefore in the TCB, not only AMD.
2. **The Confidential Space image and launcher.** The launcher measures the
   container, enforces the image's launch policy, and obtains the attestation
   token from Google's attestation service.
3. **Google's attestation service, STS and IAM.** They issue the token,
   exchange it for federated credentials, and evaluate the workload identity
   federation (WIF) condition that gates KMS.
4. **Cloud KMS and its HSMs.** They hold the private key and enforce IAM on
   `AsymmetricDecrypt`.
5. **The enclave image** at the digest you allow: its code and its pinned
   dependencies. Anyone can rebuild it and compare digests (see
   [VERIFY.md](VERIFY.md)).
6. **The owner's device and the CLI.** They see plaintext at sealing time and
   hold the owner seed.

The server, its database, the network, the VM host and the other tenants are
**not** in the TCB.

## Trust boundaries

```
 owner device ──(1) seal to KMS pubkey, sign──▶ server (untrusted store)
 agent ──(2) TLS pinned by attestation──▶ enclave (CVM)
 enclave ──(3) HTTPS + attestation bearer token──▶ server
 enclave ──(4) STS/WIF + AsymmetricDecrypt──▶ Cloud KMS (HSM)
 enclave ──(5) HTTPS, policy-checked──▶ upstream API
```

1. **Owner → server.** Plaintext never crosses this boundary. The CLI seals
   each secret to the KMS public key of the enclave it has *verified* (it
   refuses if the server reports a different key), and signs the envelope,
   including its policy, with the owner key. API keys are generated on the
   device; the server receives only a lookup hash and an owner-signed grant.
2. **Agent → enclave.** The agent connects over TLS to a certificate whose
   public key is bound into the attestation token (`eat_nonce = boot_id =
   sha256(tls_spki ‖ receipt_pub)`). The CLI and SDK pin that certificate
   after `carapace verify`.
3. **Enclave → server.** The enclave authenticates with an attestation token
   whose audience is the control-plane URL. It treats everything the server
   returns as untrusted and verifies owner signatures itself.
4. **Enclave → KMS.** The enclave exchanges an attestation token with a
   separate STS audience for federated credentials. Only a principal whose
   token satisfies the WIF condition holds `cloudkms.cryptoKeyVersions.useToDecrypt`.
5. **Enclave → upstream.** The enclave enforces the owner-signed policy on
   every outbound request and redacts the secret from responses.

## Guarantees and what enforces them

Each guarantee below assumes the TCB is intact.

| # | Guarantee | Enforced by |
|---|---|---|
| G1 | Only an attested enclave running an allowed image digest can unwrap a DEK. | KMS key IAM policy (authoritative) grants decrypt only to WIF principal sets keyed on `image_digest`; the WIF condition also requires the STS audience, `swname = CONFIDENTIAL_SPACE`, `hwmodel = GCP_AMD_SEV`, `dbgstat = disabled-since-boot`, secure boot, the `STABLE` support attribute, the project id, the enclave service account, and the container env's `CONTROL_PLANE_URL`, `KMS_KEY_NAME` and `WIF_AUDIENCE` equal to the values the VM is launched with. The key ring policy is authoritative and empty. (`infra/pulumi/components/wif.py`, `kms.py`) |
| G2 | The server cannot read secrets. | Client-side sealing to the KMS public key (`packages/crypto`); the server never holds decrypt permission. |
| G3 | The server cannot substitute a secret, widen a policy, or attach a secret to a key the owner did not authorize. | Ed25519 owner signatures over envelopes (policy bound into signature and AES-GCM AAD) and grants; the enclave verifies both against the owner fingerprint embedded in the API key. (`packages/crypto`, `enclave/.../broker.py`) |
| G4 | An API key record the server invents is useless. | A grant binds `key_bind = bind_hash(raw key)`. The server stores only the separately-tagged `lookup_hash`, so it cannot compute `bind_hash` for a key it did not see, and cannot move a grant from one key to another. |
| G5 | An agent can use a secret only within its policy. | Enclave policy check: HTTPS only, host/suffix allowlist, method and port lists, DNS resolved once with private/link-local addresses blocked and the connection pinned to the resolved IP, agent headers that could redirect or impersonate the credential rejected (`Host`, `Forwarded`, `X-Forwarded-*`, `Proxy-*`, framing headers, the injected header itself), no redirects, size caps, per-owner and per-policy rate limits. |
| G6 | The agent does not receive the raw secret in responses. | Redaction of raw, base64 (standard and URL-safe, any alignment), percent-encoded, JSON-escaped and hex forms from response headers and body. **Best-effort:** see [residual risks](#residual-risks). |
| G7 | The client talks to the enclave it verified, not a man in the middle. | `carapace verify` checks the Google-signed token (RS256 via Google's OIDC JWKS, audience `carapace-attestation`, `eat_nonce = boot_id`), the platform claims, the image digest against `--allow-digest`, the deployment (project id, enclave service account, and the container env's `CONTROL_PLANE_URL` and `KMS_KEY_NAME`) against the values the user passes or `carapace deploy` takes from the stack, and that the attested TLS key equals the peer's certificate; later calls trust only the pinned certificate, and `audit verify` checks past boots against the same pinned deployment. |
| G8 | Every authorized use leaves a signed, hash-chained receipt that the server cannot forge or reorder undetected. | Per-boot Ed25519 receipt key bound into the attestation nonce; receipts chain by `prev_hash`; `carapace audit verify` checks each boot's token, signatures, chain links and `owner_fp`. The enclave stops serving if it cannot hand receipts to the server (fails closed at a 1 000-receipt backlog or on a 409/422). |
| G9 | A malicious server's replay of old owner-signed objects is bounded in time. | Grant expiry (default 30 days, max 90), per-secret version floors in grants, and a best-effort per-boot monotonic cache. See [design/owner-signing.md](design/owner-signing.md#freshness-rollback-and-revocation). |
| G10 | The VM host cannot roll the enclave's clock back to revive an expired grant. | `now = max(VM clock, iat of the latest attestation token)`, monotonic within a boot; tokens refresh every 15 minutes and gate KMS access, so an enclave cut off from refresh loses KMS within about an hour. |
| G11 | No shell or ambient authority inside the enclave. | Distroless image, no shell, UID 65532; launch policy refuses command overrides and allows only the `CONTROL_PLANE_URL`, `KMS_KEY_NAME` and `WIF_AUDIENCE` env overrides. The image is built so nothing needs to write to its filesystem (no bytecode, no temp files), but the Confidential Space launcher does **not** mount the root filesystem read-only and nothing in the stack enforces it; not writing to disk is a property of the enclave code, not a mount option. |
| G12 | Tampering with who can decrypt is visible. | Cloud Audit Logs plus a log-based alert (`infra/pulumi/components/monitoring.py`). See R1. |
| G13 | A stranger cannot open an account on a self-hosted server and use its enclave as an egress proxy. | Registration (password and passkey) is closed once any account exists, unless the operator sets `CARAPACE_ALLOW_SIGNUP=true` (`carapace:allow_signup`), off by default; a closed registration is a 403 `Registration is closed`. The first account takes a one-row `instance_claim` table (primary key fixed to 1 by a check constraint) in the same transaction as the user, so of two concurrent first registrations the database lets exactly one commit, on Postgres and SQLite alike. The first registration must also present the one-time setup token whose SHA-256 is `CARAPACE_SETUP_TOKEN_SHA256`, compared in constant time; the claim consumes it. In `prod` a server with no hash configured refuses the first registration (403 `Invalid setup token`). Migration 0002 claims an existing server for its oldest account. (`server/.../auth/service.py`) See R15. |

## Residual risks

These are known, accepted for v0.1, and out of scope as vulnerability
reports unless you show they are worse than stated.

### R1. A GCP project Owner can decrypt

The KMS key's IAM policy is authoritative, so `pulumi up` removes any extra
binding on the key. It does **not** remove roles inherited from the project,
folder or organization. The basic Editor role carries no decrypt permission
(checked, below). Whether `roles/owner` itself carries
`cloudkms.cryptoKeyVersions.useToDecrypt` was not checked, and does not
matter: an Owner can change IAM, so it can grant itself (or anyone) a Cloud
KMS role that decrypts, on the key or on the project, and then call
`AsymmetricDecrypt` without an attested enclave. A project Owner can also
loosen the WIF condition, add an image digest, or create a new key version.
Each of those IAM or key changes is an Admin Activity audit log entry, which
cannot be turned off, and any decrypt by a caller outside the stack's WIF
pool is a Data Access log entry that matches the alert's foreign-decrypt
clause (below).

An Editor cannot change IAM policies, so it cannot decrypt unless it also
holds a Cloud KMS role that allows it (granted directly, or inherited from a
folder or organization). This matters because GCP grants the default
Compute Engine service account Editor on new projects: that grant alone
does not reach the key. Checked on real GCP on 2026-09-26, with `gcloud iam
roles describe roles/editor` and the key's IAM policy: `roles/editor` has
no `cloudkms.cryptoKeyVersions.useToDecrypt`, no
`cloudkms.cryptoKeys.setIamPolicy`, and no write permission on workload
identity pools or their providers (no `iam.workloadIdentityPools.*` write
and no `iam.workloadIdentityPoolProviders.create`, `.update` or `.delete`),
so it cannot loosen the WIF condition, its attribute mapping or its issuer
either. The key's policy held only the attested digest principal set
(`roles/cloudkms.cryptoKeyDecrypter`) and the server service account
(`roles/cloudkms.publicKeyViewer`).

What an Editor can reach is the enclave VM. `roles/editor` does carry
`compute.instances.setMetadata` and `iam.serviceAccounts.actAs`, so it can
change the VM's launcher metadata, stop it, or replace it with a VM of its
own running as the enclave service account. None of that reaches the key:
a different image has a different digest, outside the principal set; a
different `CONTROL_PLANE_URL`, `KMS_KEY_NAME` or `WIF_AUDIENCE` fails the
WIF condition; and the launcher refuses env overrides the image's launch
policy does not list. Decrypt fails closed, and `carapace verify` refuses
an enclave that is not the pinned one. The effect is on availability only.
(The same role can redeploy the control plane and its database, which this
model already treats as untrusted: see the server operator row above.)

Detection, not prevention: when `enable_iam_alerts` is on (the default), a
log-based alert emails `alert_emails` on KMS `SetIamPolicy`,
`CreateCryptoKeyVersion`, `ImportCryptoKeyVersion` and
`UpdateCryptoKeyPrimaryVersion` in the key ring; IAM changes on the WIF pool;
changes to the enclave service account; project `SetIamPolicy` (which also
covers turning off Data Access audit logs); changes to log sinks,
exclusions, buckets and settings; changes to the alert policy or its
notification channels; and any `AsymmetricDecrypt` whose caller is not a
principal of this stack's WIF pool. The alert is rate limited to one
notification per 5 minutes. It does **not** watch folder- or
organization-level IAM changes. A project Owner can also delete the alert
policy or its notification channel. That change matches the filter too, but
whether the notification still goes out when the policy itself is being
deleted has not been tested. Treat the alert as a tripwire against mistakes
and slow attackers, not as a control.

For self-hosters, the project owner is you. For a hosted deployment, the
operator is in this position, and the owner cannot currently see the KMS IAM
policy from the client side. Publishing it through `/attestation` is an open
question for a later version.

### R2. A malicious server can delay revocation until the grant expires

The server stores grants and envelopes and the enclave fetches them on every
request, so a malicious server can keep serving a revoked key's last live
grant, or an older envelope, until that grant's `exp` (default 30 days,
maximum 90, set with `carapace key create --ttl-days`).

`carapace key revoke` uploads an owner-signed **tombstone** grant (no
secrets, newer `iat`). An honest server serves it immediately. It helps only
partially against a malicious server: once the enclave has verified the
tombstone in the current boot, the monotonic cache refuses the older grant
for the rest of that boot, but the cache is best-effort (LRU-bounded,
flushable by traffic under many owner keys) and resets on every reboot, and a
server that never serves the tombstone is not detected. The CLI prints this
on every revoke. **The only hard cutoff is rotating the credential at its
provider.**

### R3. A database writer can mint API key records, but not working keys

Anyone with write access to the database can insert API key rows. Such a key
only works with an owner-signed grant whose `key_bind` matches the raw key,
and the server cannot produce one (G4). A server-minted key therefore gets
nothing the owner did not sign. What the server *can* do is replay an
existing key's grant to that same key within its lifetime (R2), and deny
service.

### R4. There is no `key renew`

`carapace key renew` was designed but removed from v0.1. A grant names the
API key it authorizes only by `key_bind`, which the CLI cannot link to the
key id the server lists. Renewing would mean re-signing a grant the server
supplied with a fresh expiry, and a lying server could hand the CLI a
revoked key's last live grant under another key's id and get it re-signed.
To extend access, create a new key and revoke the old one. The design is
[deferred](design/owner-signing.md) until grants name their key.

### R5. The CLI does not verify release signatures

CI signs the enclave image and a release manifest (`releases/<tag>.json`)
with keyless cosign, but the CLI does not check either. `carapace verify`
trusts exactly the digests you pass with `--allow-digest`. Deciding which
digest to allow is up to you: rebuild the image yourself, or check the
manifest with `cosign verify-blob` and compare its `digest` to what you pass.
See [VERIFY.md](VERIFY.md).

### R6. Refused requests leave no receipt

Receipts are written only once a request has been authorized and its
envelope verified, for the outcomes `ok`, `denied` (blocked by the egress
policy) and `error` (upstream failure). The enclave writes **no** receipt
for an unknown or revoked key (401 `invalid_api_key`), a key whose grant
does not cover the secret (403 `forbidden`, as opposed to 403
`egress_denied`, which is receipted as `denied`), malformed requests (400),
oversized bodies (413), rate limiting (429), control-plane store errors
(502), or when receipts or attestation are unavailable (503). Failed attempts with a stolen or revoked key, and probing, therefore
do not appear in `carapace audit verify`. They appear only in the enclave's
container logs (Cloud Logging in the deploying project), which are not
signed.

`carapace audit verify` reports chain gaps as a count rather than a failure,
because receipts belonging to other owners on a shared enclave also appear
as gaps. A server that withholds some of your receipts produces gaps that
look the same.

### R7. The enclave has a public IP on port 8443

The enclave VM has a static external IP with a firewall rule allowing
`tcp:8443` from anywhere. Nothing else is exposed. This is intentional: the
agent's TLS session terminates inside the enclave, and the certificate is
pinned through attestation (G7), so a network path through Google's front
ends would add trust without adding security. Exposure is limited to the
enclave's own HTTP handler, which is rate limited per peer (30 auth
failures/min), per owner (600 requests/min) and in concurrency (256
connections). It is a denial-of-service surface.

### R8. Secrets cannot be reliably wiped from memory

The enclave is written in Python. DEKs and plaintext pass through immutable
`bytes` objects and library buffers (the TLS stack, `httpx`, JSON parsing),
and the enclave cannot zero them. It keeps secrets in memory only (the code
never writes to disk; the root filesystem is writable, see G11), caches DEKs
for at most 60 s, and zeroes the mutable buffers it controls
(`secure_memory.py`), but copies may remain in freed heap memory until
reused. SEV encrypts guest memory against the host; this matters only if
enclave code is compromised.

### R9. Redaction is not complete

Redaction covers the encodings listed in G6. It does not cover UTF-16,
HTML entities, case changes, nested or partial encodings, or an upstream
that transforms the secret in some other way. An upstream API (or an agent
able to choose the upstream URL within the allowlist) that reflects the
credential in a transformed form can leak it. Keep policies narrow.

### R10. The upstream API sees the secret

By design, the credential is sent to every host the policy allows. A host
on the allowlist that is compromised, or that echoes request headers, sees
it. The policy is the control.

### R11. Freshness and clock

A malicious server can serve older owner-signed objects until they expire
(R2). The enclave's clock can be held still, but not turned back, for about
an hour (G10). Within that window it can serve only objects that were valid
at the frozen time. This bound depends on the enclave never caching
anything beyond the 60 s DEK cache, and on federated credentials expiring as
documented by Google (not yet observed on real hardware).

### R12. The owner's device is trusted

Malware on the owner's device can read secrets as they are sealed and use
the owner seed. The passphrase on `owner-key.json` is optional
(`carapace init --no-passphrase`).

### R13. Offline audit is not fully offline

`carapace audit verify` needs a logged-in session and the owner key (it
prompts for the passphrase, to derive the fingerprint receipts are checked
against), even with `--file`, and fetches Google's JWKS over the network to
check each boot's attestation token. Checking a token after Google has rotated the signing key out of
its JWKS is expected to fail (not yet observed).

### R14. Shared enclave between tenants

On a hosted deployment one enclave serves every tenant. Isolation between
tenants is enforced in software by the broker (owner fingerprints,
signatures, per-owner caches and limits), not by hardware. A bug in the
enclave code affects every tenant.

### R15. The first account and the setup token

`carapace deploy` generates a 256-bit setup token in memory, puts only
its SHA-256 in the stack config (`carapace:setup_token_sha256`, stored
in plaintext in the gitignored `Pulumi.<prefix>.yaml` and on the Cloud Run
service as `CARAPACE_SETUP_TOKEN_SHA256`), and sends the token once, to
sign up the owner. The hash is not a secret: nothing short of guessing a
256-bit value turns it into a token. What remains:

- Anyone who can read the deployer's process memory during the deploy, or
  who can change the Cloud Run service's environment before the owner
  signs up (a project Owner or Editor), can claim a fresh server first.
  Both are already trusted further than that (R1, R12).
- Between `pulumi up` and the first run's sign-up (seconds, in
  `carapace deploy`) the server is unclaimed, but only the token holder can
  claim it. A manual deployment that sets no hash cannot be claimed at
  all in `prod` until one is set (see
  [SELF_HOST.md](SELF_HOST.md#6-first-run-verify-the-enclave)). In `dev`
  mode with no hash, the first registration wins without a token.
- `allow_signup=true` reopens registration to everyone, by design, for a
  hosted multi-tenant server; tenants then share the enclave (R14).
- The concurrent-first-registration race is tested on SQLite; on Postgres
  it rests on the same primary-key uniqueness, which has not been
  exercised under concurrency in CI.

## Unverified assumptions

The following have only been checked against documentation and tests with
mocks. They need confirmation on real Confidential Space hardware before
v0.1 is tagged. If one is wrong, the system should **fail closed** (nothing
decrypts), except where noted.

- The `principalSubject` recorded in Data Access logs for federated callers
  matches the pool prefix the alert allows. If it does not, every enclave
  decrypt alerts (noisy, but fails safe).
- The KMS Data Access `methodName` for decrypt is `AsymmetricDecrypt` as the
  alert filter expects. If it is not, **unauthorized decrypts would not
  alert** (fails open for detection only).
- STS-federated credentials can call `GetPublicKey` with
  `roles/cloudkms.publicKeyViewer`.
- A non-confidential VM, or the server service account, actively calling
  decrypt gets `PERMISSION_DENIED`. The key's IAM policy was inspected (see
  below), but no such call was made.
- The two CI builders produce the same digest in practice (a `--build`
  digest has not been compared against a release build).

### Verified on real GCP

Checked once on 2026-09-26, in a throwaway project in `us-east1`, with
images built from source by `carapace deploy --build`:

- The attestation token carries `submods.container.env.CONTROL_PLANE_URL`,
  `KMS_KEY_NAME` and `WIF_AUDIENCE` as a map from name to value. The WIF
  condition pinning all three was satisfied, and `carapace verify` with the
  deployment identity pins passed.
- The `image_digest` claim matched the pinned platform manifest digest, and
  a WIF principal set keyed on a `sha256:` attribute value was granted
  decrypt as written.
- The launcher accepted the image's launch policy, and the enclave was
  reachable on port 8443.
- Real decrypt, header injection and response redaction worked through the
  enclave (against httpbin.org), and a request to a host outside the
  policy's allowlist was denied.
- `carapace audit verify` passed with 2 receipts from 1 attested boot.
- The KMS key's IAM policy held only the digest principal set
  (`roles/cloudkms.cryptoKeyDecrypter`) and the server service account
  (`roles/cloudkms.publicKeyViewer`).
- `gcloud iam roles describe roles/editor` on the live project: the role
  has no `cloudkms.cryptoKeyVersions.useToDecrypt`, no
  `cloudkms.cryptoKeys.setIamPolicy`, and no write permission on workload
  identity pools or their providers, so the Editor grant GCP gives the
  default Compute Engine service account can neither decrypt nor loosen
  the WIF condition. It does have `iam.serviceAccounts.actAs` and
  `compute.instances.setMetadata`: an Editor can reconfigure, stop or
  replace the enclave VM, which fails closed for decrypt (see R1).

Checked again on 2026-09-28, in a throwaway project in `us-central1`,
deployed from the published release `v0.1.0-rc.3` with plain `carapace
deploy` (no `--build`):

- `carapace deploy` downloaded and verified the signed release manifest,
  copied the enclave and server images from GHCR into Artifact Registry
  by digest, and pinned the WIF condition to that digest.
- First-run `carapace verify` passed.
- A request through the enclave injected the credential, redacted the
  secret from the response, and sent `User-Agent: carapace-enclave`. A
  request to a disallowed host, and a request over plain `http://`, were
  both denied.
- `carapace audit verify` passed: 4 receipts, 1 attested boot, 0 gaps.
- The web UI was exercised against the deployed Cloud Run server: login,
  secrets, keys, receipts and the attestation page all worked, with no
  CSP or Trusted Types console errors and no token in web storage; a
  reload logged the session out (the attestation page reports the
  enclave as unverified until `carapace verify` is run, by design).
- Revoking a key in the web UI made the enclave reject that key on its
  next request.
- The first attempt hit an `n2d-standard-2` capacity stockout in every
  `us-central1` zone; re-running the same `carapace deploy` command
  resumed and completed.
