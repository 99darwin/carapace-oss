# Verifying an enclave and its receipts

Carapace asks you to trust a specific enclave image, not an operator. This
guide covers the three checks that make that concrete:

1. [Decide which image digest to trust](#1-decide-which-image-digest-to-trust),
   by rebuilding the image or checking the signed release manifest.
2. [Verify a running enclave](#2-verify-a-running-enclave) with
   `carapace verify`, which checks its attestation and pins its TLS key.
3. [Verify receipts](#3-verify-receipts) with `carapace audit verify`.

See [THREAT_MODEL.md](THREAT_MODEL.md) for what these checks do and do not
protect against.

> **Status: pre-alpha.** Release candidates are tagged and signed by CI,
> but no deploy from a published release has run end to end yet.
> `carapace verify`, with the deployment identity pins, and
> `carapace audit verify` have passed once against a real Confidential
> Space enclave (2026-09-26, built from source); see [THREAT_MODEL.md,
> Verified on real GCP](THREAT_MODEL.md#verified-on-real-gcp). The release
> download and sigstore path is still unverified.

## 1. Decide which image digest to trust

`carapace verify` trusts exactly the digests you give it with
`--allow-digest`. It does **not** check release signatures itself. Choosing
the digest is the step that carries your trust, so do it deliberately.

The digest of record is the **linux/amd64 image manifest digest**
(`sha256:…`), not the digest of the multi-platform index that a registry
tag resolves to. The index also holds provenance and SBOM attestations,
which record builder details and differ from build to build. The manifest
digest is what the enclave VM runs, what the attestation token's
`image_digest` claim reports, and what the KMS access policy allows.

### Option A: rebuild the image yourself

This is the strongest check: it ties the digest to source you can read.

Requirements: Docker with buildx and the `docker-container` driver
(`rewrite-timestamp` needs it), and a checkout of the exact commit.

```bash
git clone https://github.com/<owner>/<repo>.git carapace && cd carapace
git checkout <tag or commit>

# The BuildKit version pinned in .github/actions/build-enclave/action.yml.
docker buildx create --name carapace-repro --driver docker-container \
  --driver-opt image=moby/buildkit:v0.33.0@sha256:6c2fa84a6b61ccd72899dde4239f8d5717f05f9a8ca6f3cad185fb1a95a94de3

docker buildx build --builder carapace-repro -f enclave/Dockerfile \
  --platform linux/amd64 --provenance=mode=max --sbom=true --no-cache \
  --build-arg SOURCE_DATE_EPOCH="$(git log -1 --format=%ct)" \
  --output type=oci,dest=enclave.tar,rewrite-timestamp=true .

python3 scripts/oci_image_digest.py enclave.tar
```

The last command prints the manifest digest. `SOURCE_DATE_EPOCH` must be the
commit time of the commit you built, because file timestamps are rewritten
to it. Always check the BuildKit pin in
`.github/actions/build-enclave/action.yml` at the commit you are building;
the one above is current as of this writing.

What makes the build reproducible: base images pinned by digest,
third-party wheels installed from a hash-locked `enclave/requirements.lock`
with `--require-hashes --only-binary=:all:`, no bytecode compiled, and
timestamps rewritten. CI builds the image on two different runner images
(`ubuntu-24.04`, `ubuntu-22.04`) and fails if the digests differ.

Known differences from CI: CI uses a pinned SBOM generator, while the
command above uses buildx's default. That changes only the SBOM attestation
inside the index, not the image manifest digest. A different BuildKit
version can change the digest; use the pinned one.

### Option B: check the signed release manifest

On a `v*` tag, CI (`.github/workflows/enclave-image.yml`) builds the image,
checks the pushed digest equals the reproduced one, pushes it to
`ghcr.io/<owner>/<repo>/enclave`, signs it with keyless cosign, and attaches
`releases/<tag>.json` (`{tag, digest, commit, epoch}`) and its cosign bundle
`releases/<tag>.json.sigstore.json` to the GitHub release.

Download both files from the release and verify the manifest's signature:

```bash
cosign verify-blob \
  --bundle "releases/${TAG}.json.sigstore.json" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  --certificate-identity-regexp \
    '^https://github\.com/<owner>/<repo>/\.github/workflows/enclave-image\.yml@refs/tags/v' \
  "releases/${TAG}.json"
```

Then check that the manifest's `tag` field is the tag you asked for (so one
release's manifest cannot be passed off as another's), and use its `digest`
with `--allow-digest`. You can also verify the image signature with
`cosign verify` and the same identity flags, by digest:
`ghcr.io/<owner>/<repo>/enclave@<digest>`.

This shows the digest came from this repository's release workflow on a
`v*` tag whose commit is on the default branch. It does not show what the
source does; Option A plus reading the diff does.

## 2. Verify a running enclave

```bash
carapace login --server https://<server> --email you@example.com
carapace verify --enclave https://<enclave ip or host>:8443 \
  --allow-digest sha256:<digest from step 1> \
  --project-id <gcp project id> \
  --service-account <enclave service account email> \
  --kms-key projects/<p>/locations/<r>/keyRings/<ring>/cryptoKeys/<key>/cryptoKeyVersions/<n>
```

Pass `--allow-digest` more than once to accept several digests, for example
during an image rollout. `verify` needs a logged-in session because it also
fetches the server's KMS public key (check 7 below).

The other three flags name the deployment you expect, and are required. For
a self-hosted stack they are the `gcp:project` config and the
`enclave_service_account` and `kms_key_version_name` stack outputs.
`--control-plane-url` defaults to the server you are logged in to (the
`control_plane_url` output); pass it only if the enclave reports to another
URL. `carapace deploy` fills in all four from the stack it just deployed.

On success it writes the pin to `enclave.json` in the config directory and
prints:

```
verified https://<enclave>:8443
boot_id  <hex>
image    sha256:<digest>
kms_key  projects/<p>/locations/<r>/keyRings/<ring>/cryptoKeys/<key>/cryptoKeyVersions/<n>
project  <gcp project id>
account  <enclave service account email>
server   https://<server>
```

### What it checks

1. **TLS key binding.** It learns the enclave's certificate with a handshake
   that sends no data, then fetches `/attestation` over a connection pinned
   to that certificate. The certificate in the attestation must be the same
   one.
2. **Token signature.** The attestation token is RS256 and signed by
   Google's Confidential Space issuer. The key comes from the issuer's OIDC
   discovery document, whose `jwks_uri` must be under `googleapis.com`.
3. **Token claims.** Audience `carapace-attestation`; not expired (60 s
   leeway); `swname = CONFIDENTIAL_SPACE`, `hwmodel = GCP_AMD_SEV`,
   `dbgstat = disabled-since-boot`, `secboot = true`, and the `STABLE`
   support attribute.
4. **Image.** The `image_digest` claim is in your `--allow-digest` list. With
   no list, verification fails.
5. **Deployment.** `submods.gce.project_id` equals `--project-id`;
   `--service-account` is in `google_service_accounts`; the container env's
   `CONTROL_PLANE_URL` equals `--control-plane-url` (both normalised: case
   of scheme and host, default port and trailing slash do not matter); and
   its `KMS_KEY_NAME` equals `--kms-key`, which the enclave must also report
   as its key version. A missing claim fails like a different one. Without
   this, an allowed image running in someone else's project would pass, and
   secrets you seal would go to that project's KMS key.
6. **Boot binding.** `eat_nonce` equals `sha256(TLS SPKI ‖ receipt public
   key)`, which binds both per-boot keys to this attested boot.
7. **KMS key.** The server's `/v1/kms/public-key` must report the same key
   and version the enclave attested to. Otherwise nothing is pinned.

Afterwards, every call to the enclave (`carapace request`, the Python SDK)
trusts only the pinned certificate, compares the peer certificate byte for
byte, and ignores proxy environment variables. `carapace secret add` repeats
check 7 and seals only to the pinned KMS key.

The pin (`enclave.json`, version 2) records the four deployment values.
Pins written by older CLIs (version 1) do not, and are refused with a
message to run `carapace verify` again: the CLI cannot tell which deployment
an old pin was verified against, so it does not guess.

### What it does not check

- **Release signatures.** See step 1.
- **`WIF_AUDIENCE`.** The enclave's STS audience is not compared. Its
  default is derived from the project *number* and the stack prefix, neither
  of which the CLI is given, and it can be overridden. The WIF condition
  pins it, so an enclave launched with another audience cannot decrypt with
  this deployment's key.
- **That the values you pass are right.** The checks are only as good as
  the flags. Take them from the stack outputs, not from the server.
- **Who can decrypt with that KMS key.** The CLI cannot see the key's IAM
  policy. See [THREAT_MODEL.md, R1](THREAT_MODEL.md#r1-a-gcp-project-owner-can-decrypt).

### When to run it again

The enclave generates fresh TLS and receipt keys on every boot, so any
restart, redeploy or image rollout changes its certificate, and pinned calls
fail. Run `carapace verify` again, and repeat step 1 if the image changed.

Rotating the KMS key (a new key version) needs a `pulumi up`, because the
WIF condition pins `KMS_KEY_NAME`, and then a `carapace verify` with the new
`--kms-key`. After that, receipts from boots that used the old key version
fail `carapace audit verify` against the new pin. Keep a copy of the old
`enclave.json` (or a config directory verified with the old key) if you
need to audit them.

### Local development

`--insecure-mock --mock-issuer-key <pem>` trusts the dev mock enclave's
issuer instead of Google. It accepts only `mock://local` tokens, is recorded
in the pin, and proves nothing about hardware. Never use it with real
secrets.

## 3. Verify receipts

Every request the enclave authorizes produces a receipt signed by that
boot's receipt key and hash-chained to the previous receipt of the boot.

```bash
carapace audit verify                  # all your receipts
carapace audit verify --secret <id>    # one secret
carapace audit fetch --output receipts.json
carapace audit verify --file receipts.json
```

`audit fetch` saves the server's pages so you can re-check them later.

### What it checks

For each boot that produced one of your receipts:

- The boot's attestation token verifies under the trust policy in your pin
  (Google issuer, platform claims, image digest in your allowlist, and the
  pinned project, service account, control plane URL and KMS key), with the
  audience set to the server URL or `carapace-attestation`, and a nonce equal
  to the boot id. Expiry is not checked, because boots are historical.
- The boot id equals `sha256(TLS SPKI ‖ receipt public key)`, so the receipt
  key is the one the hardware attested.
- The image digest the server recorded for the boot matches the token.

For each receipt:

- Its hash covers `{boot_id, seq, prev_hash, payload}` and its Ed25519
  signature verifies under the boot's receipt key.
- Sequence 0 has the all-zero `prev_hash`, and consecutive sequence numbers
  link by hash.
- The payload names your owner fingerprint.

The command prints `OK` or `FAILED` with counts of receipts, boots and gaps,
and exits non-zero on failure.

### Limits

- **Gaps are not failures.** A boot's chain interleaves every owner's
  receipts, and the server returns only yours, so missing sequence numbers
  are normal on a shared enclave. A server that withholds some of your
  receipts produces the same gaps. It cannot forge, edit or reorder the
  receipts it does return.
- **Refused requests have no receipts.** Requests refused before
  authorization (bad or revoked key, rate limited, malformed, store errors)
  are not recorded. See
  [THREAT_MODEL.md, R6](THREAT_MODEL.md#r6-refused-requests-leave-no-receipt).
- **Not fully offline.** `audit verify` needs a logged-in session, a pin
  (`enclave.json`) and the owner key (it prompts for the passphrase, to
  derive the fingerprint it checks receipts against) even with `--file`,
  and it fetches Google's JWKS to check boot tokens. Tokens signed with a key Google has since rotated out are
  expected to fail verification; this has not been observed yet.
- **Allowlist.** Boots are checked against the digests in your current pin.
  After an image rollout, run `carapace verify` with both the old and new
  digests if you want receipts from old boots to verify.
- **One KMS key version.** Boots are also checked against the pinned KMS
  key version. After a key rotation, audit old boots with the old pin (see
  [When to run it again](#when-to-run-it-again)).
