# Architecture

Carapace has one job: let an AI agent *use* a secret without ever *holding* it,
with the guarantee enforced by hardware rather than by trusting the operator.

## Components

```
agent / SDK ──attested TLS (cert pinned via eat_nonce)──▶ ENCLAVE (CVM :443)
CLI / web   ──encrypt locally to KMS public key──────────▶ SERVER (untrusted)
ENCLAVE     ──pulls ciphertext, auth = attestation JWT───▶ SERVER
ENCLAVE     ──WIF principalSet(image_digest)─────────────▶ Cloud KMS (HSM)
```

| Component | Trust | Role |
|---|---|---|
| **Enclave** | Trusted (attested) | Decrypts secrets, performs egress requests with the credential injected, redacts responses, signs receipts |
| **Server** | Untrusted | Accounts, API keys, ciphertext and policy storage, receipt storage. Never sees plaintext. Not in the request data path. |
| **CLI / SDK / web** | User's device | Verifies attestation, encrypts secrets locally, sends agent requests to the enclave |
| **Cloud KMS** | Google TCB | Holds the asymmetric decryption key; releases decryption only to the attested workload |

## Key management

- One Cloud KMS key: `ASYMMETRIC_DECRYPT`, `RSA_DECRYPT_OAEP_4096_SHA256`,
  protection level `HSM`.
- `roles/cloudkms.cryptoKeyDecrypter` is granted **only** to a Workload
  Identity Federation `principalSet` keyed on the enclave image digest. The
  WIF provider condition requires `hwmodel == GCP_AMD_SEV`,
  `swname == CONFIDENTIAL_SPACE`, `dbgstat == disabled-since-boot`, and
  `secboot == true`.
- The server's service account holds only `roles/cloudkms.publicKeyViewer`.
- No service account attached to the VM has KMS permissions, and the enclave
  has no fallback to ambient credentials.

## Envelope format (v1)

```
dek      = random(32)
aad      = sha256(canonical_json({v: 1, secret_id, owner_id, policy}))
ct       = AES-256-GCM(dek, nonce, plaintext, aad)
wrapped  = RSA-OAEP-SHA256(kms_public_key, dek)
stored   = {secret_id, owner_id, policy, kms_key_version, wrapped, nonce, ct}
```

The policy is stored in cleartext because the enclave needs to read it, but
the enclave recomputes the AAD from the stored policy. An operator who widens
a secret's allowlist makes decryption fail.

## Attestation and client verification

At boot the enclave generates a TLS key pair and an Ed25519 receipt key, then
requests a Confidential Space token with
`eat_nonce = sha256(tls_spki_der || receipt_pubkey)`. `GET /attestation`
returns the token, TLS certificate, receipt public key, and KMS public key.

`carapace verify`:

1. Verifies the token signature against Google's published JWKS, plus the
   issuer, audience, and expiry.
2. Checks the hardware, software, debug, and secure-boot claims.
3. Checks that the container image digest appears in a signed release
   manifest.
4. Checks that the nonce binds the served TLS certificate and receipt key.
5. Pins the TLS certificate for all further enclave connections.
6. Refuses to encrypt if the KMS public key from the server differs from the
   one in the attested response.

## Injection policy

Every secret carries a policy:

```json
{
  "v": 1,
  "hosts": [{"match": "exact", "value": "api.github.com"}],
  "schemes": ["https"],
  "methods": ["GET", "POST"],
  "ports": [443],
  "inject": {"kind": "header", "name": "Authorization",
             "template": "Bearer {secret}"},
  "limits": {"req_bytes": 1048576, "resp_bytes": 5242880,
             "rpm": 60, "timeout_s": 30}
}
```

For each request, the enclave executor:

- Validates the URL against the allowlist, HTTPS only.
- Resolves DNS once, blocks private and link-local addresses, and connects to
  the pinned IP to prevent DNS rebinding.
- Rejects agent-supplied `Host`, `Proxy-*`, and injection-target headers.
- Does not follow redirects.
- Caps request and response sizes.
- Redacts the secret from response headers and body, in raw, base64,
  URL-encoded, and JSON-escaped forms.
- Rate-limits per API key.
- Emits one signed receipt per request.

## Receipts

Receipts are hash-chained and signed by the per-boot Ed25519 key bound into
the attestation nonce. The server stores them verbatim along with each boot's
attestation token. `carapace audit verify` checks chains and signatures
offline. Unsigned receipts never verify.

## Residual risks

These will be documented in full in `THREAT_MODEL.md`:

- A GCP project owner can change KMS IAM. That change is visible in Cloud
  Audit Logs. Self-hosters are their own project owner.
- Anyone with database write access can mint an API key. That key can only
  use a secret within its policy, and every use is receipted.
- Google's hardware, the Confidential Space launcher, and the KMS HSMs are in
  the trusted computing base.

## Local development

`docker compose` runs the server (SQLite), a mock enclave (fake TEE socket,
`iss=mock://local`, local RSA key), and httpbin. The mock cannot reach
production, for three reasons:

- It is excluded from the production image, so any image that contains it has
  a different digest and no IAM binding.
- The production entrypoint exits if the TEE socket is absent.
- The CLI rejects mock tokens unless `--insecure-mock` is passed.
