# `carapace deploy` and `carapace destroy`

Status: in progress. It lands as stacked PRs: this design and the
interview; preflight and the confirmation summary; state and Pulumi
orchestration; then images, first run, resume and destroy. Nothing in it has been run against a real project yet
(see [Unverified](#unverified)).

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
   account, run the existing `verify` flow against the new enclave with the
   deployed digest as the only allowed one, and save the pin, so
   `carapace secret add` works next. The deploy knows the whole deployment
   identity (project id, enclave service account, control plane URL and
   KMS key name), so it passes all four to `verify` and into the pin once
   `TrustPolicy` enforces them (branch security/pin-deployment-identity).
   The deploy code only calls `verify`; it does not change
   `attestation.py` or `verify.py`.

Every step is idempotent. After a failure, running the same command again
finds the existing stack in the state bucket, reads its config back as the
defaults, and continues. `carapace destroy` prints the KMS restore-window
warning from SELF_HOST.md and requires the project id to be typed back.

## Decisions

### Packaging: inline program, same interpreter

The Pulumi program stays where it is, in `infra/pulumi`, with its own
Python 3.12 venv and tests. The CLI does not shell out to that venv.
Instead it runs the program as an Automation API **inline program** in
its own interpreter. The inline function is exactly `__main__.py`:
`deploy(load_config())`, with `components` imported from the checkout. So
`StackConfig` validation (digests only, `enclave_image_digest` in
`allowed_digests`, audiences, prefix) applies unchanged, and there is only
one copy of the program.

- The deploy dependencies (`pulumi`, `pulumi-gcp`, `pulumi-random`,
  `google-auth`, `sigstore`) are the optional extra `carapace-cli[deploy]`.
  Together they are about 240 MB, which the SDK and the other commands do
  not need. The workspace dev group installs the extra, so tests import
  the real modules. Without the extra, `carapace deploy` names the
  missing extra and does nothing else.
- The pins match `infra/pulumi/requirements.txt`. All of them resolve and
  import on the workspace Python (3.12).
- v0.1 runs the CLI from a checkout (`uv sync --all-packages`, as
  SELF_HOST.md already requires), and the CLI finds the program at
  `infra/pulumi` next to its source. `CARAPACE_INFRA_DIR` overrides the
  path. Bundling `components` into a published wheel is left for when the
  CLI is published.
- **Pulumi CLI binary.** The Automation API needs it. If `pulumi` is on
  `PATH` and satisfies the SDK's minimum version, the CLI uses it.
  Otherwise it asks before `PulumiCommand.install` downloads the matching
  version into `~/.pulumi/versions/`, and it never does so in
  non-interactive mode without `--install-pulumi`. The provider plugins
  (`gcp`, `random`) are installed at the versions of the installed Python
  packages, so the program and its providers never drift.

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
  ciphertext in state. The CLI passes `show_secrets=False` to `up` and
  `destroy` (the Automation API default is `True`), never exports the
  stack, and keeps its inline work directory in the private config
  directory. The stack config it writes holds no secrets.

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
- `--build` runs `docker buildx` locally (docker is needed only then) and
  reads the pushed `linux/amd64` digest back from the registry.

### Resume and updates

- The stack name is the prefix, so one project can hold several
  deployments with different prefixes. A re-run finds the stack in the
  state bucket and offers its config (region, zone, alert emails) as the
  defaults, then offers to update or resume.
- Switching the enclave to a new digest takes two `up`s. The first allows
  both the old and the new digest while the VM is replaced, so the running
  enclave keeps KMS access until the new one has booted. The second allows
  only the new digest.

## Unverified

These are exercised only with mocked HTTP and a mocked Automation API.
They need a real project:

- The GCS backend and `gcpkms://` secrets provider with ADC user
  credentials.
- Resource Manager, Cloud Billing and `testIamPermissions` responses for a
  fresh project, including which of them work before any API is enabled.
- The Artifact Registry token flow and blob upload in the Python copier,
  and that the pushed digest matches.
- The sigstore bundle format that cosign v3 `sign-blob --bundle` emits.
- The time it takes the HSM key version to reach `ENABLED`, and for the
  enclave to boot and register.
