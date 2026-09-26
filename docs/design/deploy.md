# `carapace deploy` and `carapace destroy`

Status: in progress. It lands as stacked PRs: this design and the
interview; preflight and the confirmation summary; state and Pulumi
orchestration; then images, first run, resume and destroy. It has run end
to end once against a real project, with `--build` (see [Verified on real
GCP](#verified-on-real-gcp)); the release path and `destroy` have not (see
[Unverified](#unverified)).

## Goal

One command, `carapace deploy`, deploys the stack from
[SELF_HOST.md](../SELF_HOST.md) into the user's own GCP project. It asks for
what it needs. Every question also has a flag, so it can be scripted. With
`--non-interactive`, or when stdin is not a terminal, a missing required
value is an error. It never waits for input that cannot come.

## Flow

1. **Preflight (read only).** Load ADC credentials, pick the project (from
   the Resource Manager project list when interactive), check billing and
   the caller's permissions, and pick a region that has both N2D
   Confidential VMs and Cloud KMS HSM. Validate the alert email. Print a
   summary: what gets created, about $80/month, and residual risk R1
   (a project Owner can grant itself decrypt, so use a dedicated project).
   Nothing changes until the user confirms, or passes `--yes`.
2. **State backend.** Create the state bucket and the state key if they are
   missing (see below).
3. **Bootstrap.** `pulumi up` with `deploy_workloads=false`. Then wait
   until KMS reports the HSM key version as `ENABLED`.
4. **Images.** Copy the release images into the stack's Artifact Registry
   repository by digest, after verifying them. `--build` builds them
   locally instead.
5. **Workloads.** `pulumi up` with the digests and `deploy_workloads=true`.
   Pulumi runs the migration job and waits for it (the job is part of the
   stack). The CLI then checks that the job's latest execution succeeded.
6. **First run.** Create the owner key if there is none, sign up the first
   account (or log in, if it exists), register the owner key, run the
   existing `verify` flow against the new enclave with the deployed digest
   as the only allowed one, and save the pin, so `carapace secret add`
   works next. See [First run](#first-run).

Every step is idempotent. After a failure, running the same command again
finds the deployment record in the state bucket, uses its region, zone and
alert emails as the defaults, and continues (see
[Resume and updates](#resume-and-updates)). `carapace destroy` prints the KMS restore-window
warning from SELF_HOST.md and requires the project id to be typed back.

## Decisions

### Packaging: the `pulumi` CLI in `infra/pulumi`

The Pulumi program stays where it is, in `infra/pulumi`, with its own
Python 3.12 venv, pins and tests. The CLI runs the `pulumi` CLI as a
subprocess (an argv list, never a shell) in that directory, which is
exactly what SELF_HOST.md does by hand. So `StackConfig` validation
(digests only, `enclave_image_digest` in `allowed_digests`, audiences,
prefix) applies unchanged, and there is only one copy of the program.

- **Why not the Automation API.** The first draft ran the program inline
  through the Automation API, which puts the Pulumi Python SDK in the
  workspace. The SDK requires `protobuf<7`, and the workspace has a single
  lock, so adding it downgraded the enclave's `protobuf` (7.36.2 to
  6.33.6, caught by the `requirements.lock` test). The enclave's
  dependencies must not move for a deploy tool, so the CLI keeps no Pulumi
  Python dependency at all. The Automation API only wraps the same CLI
  commands anyway.
- **Commands.** `pulumi stack select --create --secrets-provider
  gcpkms://...` (idempotent), `pulumi install` (creates `infra/pulumi/venv`
  from `requirements.txt` and the provider plugins), `pulumi config
  --json`, `pulumi config set-all --plaintext ...`, `pulumi up --yes
  --skip-preview`, `pulumi stack output --json` and `pulumi destroy`. All
  run with `--non-interactive`, `PULUMI_BACKEND_URL=gs://...` and
  `PULUMI_SKIP_UPDATE_CHECK=true`. `up`, `destroy` and `install` stream
  their output to stderr.
- **The deploy extra** `carapace-cli[deploy]` holds only what the CLI
  itself imports (`google-auth`, later `sigstore`).
- v0.1 runs the CLI from a checkout (`uv sync --all-packages`, as
  SELF_HOST.md already requires), and the CLI finds the program at
  `infra/pulumi` next to its source. `CARAPACE_INFRA_DIR` overrides the
  path. Shipping the program with a published CLI is left for when the
  CLI is published.
- **Pulumi CLI binary: not auto-installed.** `pulumi` 3.x must be on
  `PATH`; otherwise the deploy stops before changing anything and links
  the install page. Downloading and running an installer is a step the
  user should take knowingly, and every other prerequisite (gcloud, uv)
  is already the user's to install.
- The stack config file `infra/pulumi/Pulumi.<prefix>.yaml` is where
  Pulumi keeps it for the manual path too. It is gitignored and holds no
  secret values, only the `gcpkms` provider and its wrapped data key.

### State backend: GCS plus a dedicated `gcpkms://` key

State lives in `gs://<project>-carapace-state` in the user's project.
Secrets in it are encrypted with
`gcpkms://projects/<p>/locations/<region>/keyRings/carapace-state/cryptoKeys/pulumi-state`,
a software `ENCRYPT_DECRYPT` key in its own key ring.

- **No Pulumi Cloud account and no passphrase.** Nothing to lose, and
  nothing to type in scripts. The state survives the loss of the laptop.
  Access follows project IAM, which is already the root of trust
  (R1: an Owner can decrypt anyway), so it adds no new party.
- **A separate key and key ring, never the HSM key.** The HSM key is
  `ASYMMETRIC_DECRYPT`, its policy is authoritative and names only the
  attested WIF principals, and its key ring's policy is pinned to empty.
  Pulumi manages both, and Pulumi cannot manage the key that encrypts its
  own state. A software key is enough here, because the state secrets (the
  database password and JWT secret) already sit in Secret Manager in the
  same project.
- **Created before Pulumi runs**, through the REST APIs, idempotently: the
  bucket (uniform bucket-level access, public access prevention enforced,
  object versioning so an earlier state can be recovered) and the key ring
  and key. They are not Pulumi resources, so `destroy` leaves them.
- **No plaintext secrets on disk.** The database password and JWT secret
  are generated by `random` inside Pulumi and exist only as `gcpkms`
  ciphertext in state. No command the CLI runs passes `--show-secrets`,
  so they stay masked in the streamed output; it drops `[secret]` outputs
  and secret config entries, and never exports the stack. The stack
  config it writes holds no secrets.

Alternatives rejected: Pulumi Cloud (an account and a third party holding
state), a local backend with a passphrase (state tied to one laptop, and a
passphrase to lose or to put in scripts), and reusing the HSM key (wrong
purpose, and it would add the deployer to the one policy that must list
only the enclave).

### Images: verified release manifest, copied in Python

- **Enclave.** Download `releases/<tag>.json` and its sigstore bundle from
  the GitHub release. Verify the bundle with `sigstore` against the exact
  workflow identity
  (`https://github.com/<repo>/.github/workflows/enclave-image.yml@refs/tags/<tag>`,
  issuer `https://token.actions.githubusercontent.com`), then take the
  digest from the verified manifest. This closes R5 for the deploy path.
- **Server.** Resolve `server:<tag>` to its `linux/amd64` manifest digest.
  The server is outside the TCB. A wrong server image cannot decrypt, and
  `verify` catches a wrong KMS key. If `cosign` is installed, the CLI
  verifies the image signature too. Otherwise it says that it did not.
- **Copy.** A small OCI distribution client in Python (httpx, anonymous
  pull from ghcr.io, push to Artifact Registry with the ADC token) copies
  the blobs and then the manifest **bytes** unchanged. Before pushing, the
  CLI checks that `sha256(manifest bytes)` equals the digest. After
  pushing, it requires Artifact Registry's `Docker-Content-Digest` to equal
  it too. Neither crane nor docker is needed. Blobs that are already there
  are skipped, so a re-run is cheap. An Artifact Registry remote
  repository was considered. It would add a second repository, an extra
  IAM grant for the enclave service account, and a pull-time dependency on
  ghcr.io. It would also change the image path layout the stack assumes.
- Credentials stay on their host. ghcr.io gets an anonymous token. The
  ADC token goes only to the Artifact Registry host's own token realm, as
  basic auth for `oauth2accesstoken`. A realm on another host is refused,
  and a blob redirect (ghcr.io serves blobs from a CDN) is followed
  without the Authorization header.
- `--build` runs `docker buildx` locally (docker is needed only then) with
  the release workflow's flags into an OCI layout tarball. Docker's
  default `docker` driver cannot write one, so when the current builder
  uses it the CLI builds with a `carapace` builder instead, creating it
  (the `docker-container` driver and the release workflow's pinned
  BuildKit) if it is missing. It takes the
  `linux/amd64` image manifest from it (skipping attestation manifests,
  as `scripts/oci_image_digest.py` does) and uploads it with the same
  copier, so docker never needs registry credentials.

### Resume and updates

- The stack name is the prefix, so one project can hold several
  deployments with different prefixes. The interview asks for the prefix
  right after the project.
- Pulumi keeps stack config in `infra/pulumi/Pulumi.<prefix>.yaml`, which
  cannot be read before the stack is opened (and opening creates it). So
  the deploy writes a small record, with no secrets, to
  `gs://<project>-carapace-state/carapace/deployments/<prefix>.json`:
  project, prefix, region, zone and alert emails. It is written once the
  stack has its base config, before the first `up`.
- A re-run reads the record during preflight (read-only). Its region, zone
  and alert emails become the defaults, and the summary shows "Existing
  deployment". A different `--region` or `--zone` is refused: the stack
  would replace everything, and the state key lives in the region. If the
  bucket cannot be read (a fresh project without Cloud Storage enabled),
  that is a warning and the deploy proceeds as new.
- After opening the stack, the deploy refuses a stack whose config names
  another region or zone (say, one deployed by hand), and refuses an
  existing deployment whose `Pulumi.<prefix>.yaml` is not on this machine:
  with an empty config, the bootstrap would run on a live stack and delete
  its workloads. A stack counts as existing when the record says so or
  when the backend already has stack outputs, so an unreadable or deleted
  record cannot turn a re-run into a first deploy. The state survives the
  loss of the laptop, but the config file has to be copied to the new
  machine first.
- `Pulumi.<prefix>.yaml` is named after the prefix alone, so one machine
  holds one deployment per prefix. A config whose `gcp:project` is another
  project is refused by both `deploy` and `destroy`: an `up` with it would
  act on that project's stack. A second project needs another prefix.
- A re-run never bootstraps a stack whose workloads are live: that `up`
  would delete the VM and Cloud Run. It goes straight to the workloads
  step. Whether they are live is decided by the local config and, as a
  last check before the bootstrap `up`, by the state's `enclave_url`
  output, which exists only while `deploy_workloads` is true.
- The bootstrap `up` needs a non-empty `allowed_digests`. It uses the
  enclave digest when it is already known (release images, or
  `--enclave-digest`), and otherwise an all-zero placeholder that no image
  can have, so it grants nothing. The workloads step replaces it.
- Switching a live enclave to a new digest takes three `up`s, as in
  SELF_HOST.md: allow both digests, move the VM to the new one, then allow
  only the new one. The running enclave keeps KMS access until the new one
  has booted. Each step reads the stack config first, so a failure in the
  middle resumes at the right step.
- Image flags: the default is the latest release of
  `--release-repo` (default `99darwin/carapace-oss`); `--release <tag>`
  picks one. `--build` builds from the checkout. `--enclave-digest` and
  `--server-digest` name images already pushed to the stack's registry.
  These three are mutually exclusive. A release is downloaded and its
  signature verified before the summary, so the summary shows the
  verified digest and commit, and a bad release changes nothing.

### Destroy

- `carapace destroy --project <p> --prefix <prefix>` needs the deployment
  record, so it only destroys what `carapace deploy` made; a stack deployed
  by hand is destroyed with `pulumi destroy`, as SELF_HOST.md describes.
- It prints the KMS restore-window warning from SELF_HOST.md ("Teardown")
  and what is kept, then asks for the project id to be typed back.
  `--confirm-project <p>` confirms in scripts; there is no `--yes`.
- It turns off `protect_kms_key` and `db_deletion_protection` with one
  `up` (skipped when a failed destroy already did), runs `pulumi destroy`
  and deletes the record. Each step is idempotent, so a failed destroy is
  resumed by running it again.
- Then it runs `pulumi stack rm --yes <prefix>` (no `--force`, no
  `--preserve-config`), so the empty stack and `Pulumi.<prefix>.yaml` go
  and a later deploy with the prefix starts fresh; Pulumi's hint to run
  that command is not shown. A failed `stack rm` is reported but the
  destroy still succeeds; the stack's config is then reset (protection on,
  `deploy_workloads` false, `allowed_digests` empty) so a new deploy
  bootstraps and does not trust the dead deployment's enclave digest.
- Every deploy sets `protect_kms_key` and `db_deletion_protection` on
  again with the rest of the config it owns, so a config file left behind
  by an interrupted destroy (or a failed reset) cannot bring a deployment
  up unprotected.
- The session and enclave pin in the config directory are removed if they
  name the destroyed deployment's server and enclave URLs (read from the
  stack outputs before the destroy). If either names another deployment,
  or is a symlink or other non-regular file, the directory is left
  untouched. The owner key is always kept: it is the user's signing
  identity and may be registered elsewhere.
- The state bucket, the state key and the key ring names are kept.

### First run

- Every input it needs (account email, password, owner key passphrase) is
  collected right after the confirmation, before anything is created. A
  script without `--password-stdin`, or without `--no-passphrase` when a
  new owner key is needed, fails in seconds, not after the deploy.
  `--account-email` defaults to the first alert email.
- A saved session means a registered owner key: the key is registered
  before the session is written. A re-run reuses the session, asks for no
  password and registers the key only if the server does not list it (read
  from the key file's public half, so no passphrase is needed).
- It never replaces a session or pin in the config directory that belongs
  to another server or enclave; it asks for another `--config-dir`.
- Sign-up, owner key registration and `verify` are retried every 15s for
  up to 15 minutes on network errors, 5xx, 429 and enclave errors, while
  Cloud Run and the VM start. Any verification failure is final.
- Deployment identity. `verify` trusts only the digest this deploy
  published. The pin is then refused unless the attested KMS key version
  is exactly the stack's `kms_key_version_name`, which must be a version of
  `kms_key_name`. The project id, enclave service account and control
  plane URL are gathered into `DeploymentIdentity`, and
  `trust_policy_for` pins all of them in the `TrustPolicy` that `verify`
  enforces. The deploy does not change `attestation.py` or `verify.py`.

## Verified on real GCP

Run once on 2026-09-26 in a throwaway project in `us-east1`, from a
checkout with `carapace deploy --build`:

- The whole wizard, end to end: preflight, the GCS state backend with the
  `gcpkms://` secrets provider, the bootstrap `up` and the wait for the
  HSM key version, the `--build` images copied into Artifact Registry (the
  registry token flow, blob upload and push by digest), the workloads
  `up`, the migration job, and the first run (sign-up on a fresh database,
  owner key registration, `verify` and the pin), all within the first-run
  time limit. The enclave was reachable on `:8443`.
- Real Confidential Space tokens carry `submods.container.env`
  `CONTROL_PLANE_URL`, `KMS_KEY_NAME` and `WIF_AUDIENCE`. The WIF
  condition pinning all of them was satisfied, and `carapace verify` with
  the deployment identity pins passed.
- Real decrypt, header injection and response redaction through the
  enclave (against httpbin.org), and denial of a host outside the
  policy's allowlist.
- `carapace audit verify` passed with 2 receipts from 1 attested boot.
- The KMS key's IAM policy held only the digest principal set (decrypter)
  and the server service account (`publicKeyViewer`). `roles/editor` has
  no `cloudkms.cryptoKeyVersions.useToDecrypt`, no
  `cloudkms.cryptoKeys.setIamPolicy` and no write permission on workload
  identity pools or their providers, so the Editor grant GCP gives the
  default Compute Engine service account can neither decrypt nor loosen
  the WIF condition. It can change, stop or replace the enclave VM
  (`compute.instances.setMetadata`, `iam.serviceAccounts.actAs`), which
  fails closed for decrypt: see
  [THREAT_MODEL.md, R1](../THREAT_MODEL.md#r1-a-gcp-project-owner-can-decrypt).

That run found the problems fixed since: a private repository's release
download failed with a bare 404, `--build` failed on Docker's default
`docker` buildx driver (it cannot export OCI layouts; the CLI now uses a
`carapace` builder with the `docker-container` driver), the password
prompt checked only the length, and server 422 details were dropped.

## Unverified

These are exercised only with mocked HTTP and a fake `pulumi` process.
They need a real project:

- The release path: the GitHub release download and its redirect, and
  that the sigstore bundle cosign v3 `sign-blob --bundle` emits in the
  release workflow verifies with `sigstore` 4.x against the workflow
  identity (only a malformed bundle is tested, offline). The repository
  was private for the real run, so it used `--build`. Also ghcr.io's
  anonymous token endpoint and its blob redirect.
- `cosign verify` of the server image with the `server-image.yml`
  identity.
- Whether a `--build` digest matches the release build (it needs the same
  pinned BuildKit).
- That a non-confidential VM, or the server service account, actively
  calling decrypt gets `PERMISSION_DENIED`. Only the key's IAM policy was
  inspected.
- Which Resource Manager, Cloud Billing and `testIamPermissions` calls
  work on a fresh project before any API is enabled.
- The 400-then-login path of the first run for an existing account.
- The `pulumi stack output` behaviour on a fresh stack, and recovery of
  `Pulumi.<prefix>.yaml` from state on a second machine.
- `carapace destroy` against a real stack: the protection-lifting `up`,
  `pulumi destroy` of the HSM key (scheduling its version's destruction)
  and of the Cloud SQL instance, and the order Pulumi deletes in.
