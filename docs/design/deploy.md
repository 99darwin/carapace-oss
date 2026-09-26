# `carapace deploy` and `carapace destroy`

Status: in progress. It lands as stacked PRs: this design and the
interview; preflight and the confirmation summary; state and Pulumi
orchestration; then images, first run, resume and destroy. Nothing in
it has been run against a real project yet (see [Unverified](#unverified)).

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
   (project Owners and Editors can decrypt, so use a dedicated project).
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
finds the existing stack in the state bucket, reads its config back as the
defaults, and continues. `carapace destroy` prints the KMS restore-window
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
  the release workflow's flags into an OCI layout tarball, takes the
  `linux/amd64` image manifest from it (skipping attestation manifests,
  as `scripts/oci_image_digest.py` does) and uploads it with the same
  copier, so docker never needs registry credentials.

### Resume and updates

- The stack name is the prefix, so one project can hold several
  deployments with different prefixes. A re-run finds the stack in the
  state bucket and offers its config (region, zone, alert emails) as the
  defaults, then offers to update or resume.
- A re-run never bootstraps a stack whose workloads are live: that `up`
  would delete the VM and Cloud Run. It goes straight to the workloads
  step.
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
  plane URL are gathered into `DeploymentIdentity` and handed to
  `trust_policy_for`, the one place to set them once `TrustPolicy` enforces
  them (branch security/pin-deployment-identity, not merged yet). The
  deploy does not change `attestation.py` or `verify.py`.

## Unverified

These are exercised only with mocked HTTP and a fake `pulumi` process.
They need a real project:

- The GCS backend and `gcpkms://` secrets provider with ADC user
  credentials.
- Resource Manager, Cloud Billing and `testIamPermissions` responses for a
  fresh project, including which of them work before any API is enabled.
- The Artifact Registry token flow (realm on the registry host, basic
  auth with `oauth2accesstoken`), the monolithic blob upload streamed with
  an explicit `Content-Length`, push by digest, and the
  `Docker-Content-Digest` it returns. Also ghcr.io's anonymous token
  endpoint and its blob redirect.
- That the sigstore bundle cosign v3 `sign-blob --bundle` emits in the
  release workflow verifies with `sigstore` 4.x against the workflow
  identity (only a malformed bundle is tested, offline), and the GitHub
  release download redirect.
- `cosign verify` of the server image with the `server-image.yml`
  identity.
- `--build`: `docker buildx` writing the OCI layout with
  `rewrite-timestamp=true` on a developer machine, and whether its
  digest matches the release build (it needs the same pinned BuildKit).
- The time it takes the HSM key version to reach `ENABLED`, and for the
  enclave to boot and register, against the 15 minute first-run limit.
- The first run against a real server and enclave: sign-up on a fresh
  database, the 400-then-login path for an existing account, and a real
  attestation whose KMS key version equals the stack output.
- `pulumi stack select --create --secrets-provider gcpkms://...` against
  a `gs://` backend, `pulumi install` creating the Python 3.12 venv, and
  recovery of `Pulumi.<prefix>.yaml` from state on a second machine.
- The Service Usage, Cloud Storage and Cloud Run v2 responses the state
  backend and migration check parse.
