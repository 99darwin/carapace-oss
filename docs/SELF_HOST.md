# Self-hosting on GCP

This guide deploys Carapace into a GCP project you own, using the Pulumi
program in [`infra/pulumi`](../infra/pulumi/README.md). When you self-host,
you are the operator and the GCP project owner, so the server and project
risks in [THREAT_MODEL.md](THREAT_MODEL.md) are risks from yourself (and
anyone you give access to the project).

> **Status: pre-alpha, not yet deployed end to end.** The Pulumi program is
> tested with mocks only. It has not yet been run against a real project,
> and several steps below have **known gaps** that stop a working
> deployment today. They are marked **Gap** where they occur and listed in
> [Known gaps](#known-gaps). Do not put real secrets into a self-hosted
> deployment yet.

## What gets created

- One Cloud KMS key ring with one **HSM** key (`RSA_DECRYPT_OAEP_4096_SHA256`).
  Its IAM policy is authoritative: only workload identity federation (WIF)
  principals for the image digests you allow can decrypt.
- A WIF pool and provider for Confidential Space tokens, with a condition
  that pins the hardware, image, project, service account and control-plane
  URL.
- A Confidential VM (`n2d-standard-2`, AMD SEV) running the Confidential
  Space image with the enclave container, a static external IP, and a
  firewall rule for `tcp:8443` only.
- A Cloud Run service for the server, a Cloud SQL Postgres instance, and
  two Secret Manager secrets (database URL, JWT secret).
- An Artifact Registry repository for your images.
- Data Access audit logs for KMS, and a log-based alert on changes to who
  can decrypt (see [THREAT_MODEL.md, R1](THREAT_MODEL.md#r1-a-gcp-project-owner-or-editor-can-decrypt)).

The full list, and what is deliberately not created, is in the
[infra README](../infra/pulumi/README.md).

## Prerequisites

- A **new, dedicated GCP project** with billing enabled, and Owner on it.
  Anyone with Owner or Editor on the project (or on its folder or
  organization) can grant themselves decrypt, so keep that set small.
- A region where Cloud KMS HSM keys and N2D Confidential VMs are both
  available (the example uses `us-central1`).
- `gcloud`, authenticated with `gcloud auth application-default login`.
- Pulumi CLI 3.x and Python 3.12. Any backend works; `pulumi login --local`
  keeps state on your machine. The state contains the generated database
  password and JWT secret as Pulumi secrets, so protect it.
- Docker with buildx, to build the images.
- `uv` and the `carapace` CLI (`uv sync --all-packages --locked` in this
  repository, then `uv run carapace …`).

## 1. Configure the stack

```bash
cd infra/pulumi
python3.12 -m venv venv && venv/bin/pip install -r requirements.txt
pulumi stack init mystack
cp Pulumi.example.yaml Pulumi.mystack.yaml
```

Edit `Pulumi.mystack.yaml`. Stack files other than the example are
gitignored. At minimum set:

| Key | Value |
|---|---|
| `gcp:project`, `gcp:region`, `gcp:zone` | Your project and location |
| `carapace:prefix` | Name prefix for every resource. Pick a new one if you redeploy (see [Teardown](#teardown)) |
| `carapace:alert_emails` | At least one address that receives the IAM alert |
| `carapace:allowed_digests` | Enclave image digests allowed to decrypt (placeholder for now) |
| `carapace:enclave_image_digest` | The digest the VM runs (placeholder for now) |
| `carapace:server_image_digest` | The server image digest (placeholder for now) |

Optional keys (`control_plane_url`, `wif_audience`, machine type, database
tier, instance counts, deletion protection) are described in the
[infra README](../infra/pulumi/README.md#config-keys). Leave
`control_plane_url` unset to use the default Cloud Run URL,
`https://<prefix>-server-<project number>.<region>.run.app`. It is pinned in
the WIF condition, so changing it later changes who can decrypt.

## 2. Bootstrap without workloads

The Artifact Registry repository has to exist before you can push images to
it, so the first deploy skips the VM and Cloud Run:

```bash
pulumi config set deploy_workloads false
pulumi up
```

This creates the KMS key, WIF pool, service accounts, database, secrets,
registry, network and alerts. Note the `image_registry` output
(`<region>-docker.pkg.dev/<project>/<prefix>` by default).

## 3. Build and push the images

Images are always referenced **by digest**; tags are refused.

### Enclave

Build the enclave image reproducibly and note its manifest digest, as
described in [VERIFY.md](VERIFY.md#option-a-rebuild-the-image-yourself).
Then push the same build to `<image_registry>/enclave` and confirm the
registry serves that digest for `linux/amd64`, for example:

```bash
gcloud auth configure-docker <region>-docker.pkg.dev
docker buildx build --builder carapace-repro -f enclave/Dockerfile \
  --platform linux/amd64 --provenance=mode=max --sbom=true \
  --build-arg SOURCE_DATE_EPOCH="$(git log -1 --format=%ct)" \
  --output type=registry,name=<image_registry>/enclave:<version>,rewrite-timestamp=true .
docker buildx imagetools inspect <image_registry>/enclave:<version>
```

The `linux/amd64` manifest digest in the inspect output must equal the
digest you reproduced. If it does not, do not use it.

To deploy a published release instead, copy the image from
`ghcr.io/<owner>/<repo>/enclave@<digest>` into your registry by digest
(for example with `crane copy`). Cloud Run and the VM pull from
`image_registry`, not from ghcr.io. **Unverified:** that the copy keeps the
platform manifest digest unchanged; check it with `imagetools inspect` as
above.

### Server

**Gap:** the repository has no server Dockerfile and no workflow that
builds a server image. You need to build your own image that installs the
`carapace-server` package and runs
`uvicorn carapace_server.app:create_app --factory --host 0.0.0.0 --port 8080
--proxy-headers`, then push it to `<image_registry>/server` and note its
digest. The server is outside the trusted computing base, so this image
does not need to be reproducible, but it holds your database credentials.

## 4. Deploy the workloads

```bash
pulumi config set --path 'allowed_digests[0]' sha256:<enclave digest>
pulumi config set enclave_image_digest sha256:<enclave digest>
pulumi config set server_image_digest sha256:<server digest>
pulumi config set deploy_workloads true
pulumi up
```

`enclave_image_digest` must appear in `allowed_digests`. The outputs include
`enclave_url` (`https://<ip>:8443`), `server_url`, `control_plane_url` and
`kms_key_version_name`.

## 5. Finish the server

**Gap: database migrations.** Nothing runs the Alembic migrations against
Cloud SQL. Run them once before first use, and after every server upgrade,
with `alembic -c server/alembic.ini upgrade head` and
`CARAPACE_DATABASE_URL` pointing at the instance through the Cloud SQL Auth
Proxy. The instance accepts no direct connections (no authorized networks),
so the proxy is required. This path has not been tried.

**Gap: KMS public key.** The Pulumi program does not set
`CARAPACE_KMS_PUBLIC_KEY_PEM` and `CARAPACE_KMS_KEY_VERSION` on the Cloud
Run service. Without them `GET /v1/kms/public-key` returns 404 and
`carapace verify` fails at its last check. Until the infra sets them, you
can fetch the public key with
`gcloud kms keys versions get-public-key <n> --key … --keyring … --location …`
and set both variables on the service by hand. `CARAPACE_KMS_KEY_VERSION`
is the full `kms_key_version_name` output. The next `pulumi up` will remove
variables set outside Pulumi, so repeat this after each deploy until the gap
is closed.

## 6. First run: verify the enclave

Wait for the VM to boot and the enclave to register with the server (a few
minutes). Then, from your own machine:

```bash
carapace init
carapace signup --server "$(pulumi stack output server_url)" --email you@example.com
carapace verify --enclave "$(pulumi stack output enclave_url)" \
  --allow-digest sha256:<enclave digest>
```

Check the printed values:

- `image` is the digest you built and allowed.
- `kms_key` equals `pulumi stack output kms_key_version_name`. The CLI does
  **not** check the project, service account or KMS key name itself (see
  [VERIFY.md](VERIFY.md#what-it-does-not-check)), so this comparison is
  yours to make.

Then seal a test secret, create a key, make a request and verify the
receipt, as in the [CLI quick start](../cli/README.md#quick-start). If the
enclave does not come up, its container logs are in Cloud Logging in your
project (the VM redirects container output there), and the serial console
shows launcher errors.

## Operating it

### Rolling out a new enclave image

Three `pulumi up` runs, so the old image can still decrypt while the VM is
replaced:

1. Add the new digest to `allowed_digests`; `pulumi up`.
2. Set `enclave_image_digest` to the new digest; `pulumi up`. The VM is
   recreated and gets new per-boot keys.
3. Remove the old digest from `allowed_digests`; `pulumi up`.

After step 2, run `carapace verify` again with the new digest (and the old
one too, if you want `audit verify` to accept receipts from old boots).

### Keep the Confidential Space image current

The WIF condition requires the Confidential Space image to carry the
`STABLE` support attribute. Google retires old images over time without a
fixed schedule, and a VM keeps running the image it booted from, so a
long-lived VM eventually **stops being able to decrypt**. Run `pulumi up`
periodically (monthly is reasonable). When a newer image exists, the VM is
recreated on it, with a few minutes of downtime.

### Alerts

Alerts go to `alert_emails`. An alert means someone changed IAM on the key,
WIF pool, enclave service account, project, logging or the alert itself, or
something other than the attested enclave decrypted with the key. Treat
every unexpected alert as a potential compromise: check the Admin Activity
and Data Access logs, and rotate affected credentials at their providers.

## Cost

Rough list prices in `us-central1`, per month:

| Item | ~USD |
|---|---|
| `n2d-standard-2` Confidential VM, 24/7 | 62 |
| Static external IP (in use) | 4 |
| Cloud SQL `db-f1-micro` + 10 GB | 10 |
| KMS HSM key version (RSA 4096) | 3 |
| Cloud Run (min 0 instances), Artifact Registry, Secret Manager, Logging | ~1 |
| **Total** | **~80** |

Stopping the VM when idle brings this to about $40; the IP and the database
still bill while it is stopped. Nothing in the stack stops it
automatically. KMS operations, egress and logging volume are extra and
depend on use. These are estimates, not measured bills.

## Teardown

```bash
pulumi destroy
```

Things to know:

- **KMS key rings and keys cannot be deleted.** `pulumi destroy` schedules
  the key version for destruction (Google applies a waiting period before
  it is destroyed) and leaves the key ring name taken. Every secret sealed
  to that key becomes unrecoverable once the version is destroyed.
- The KMS key and database have deletion protection on by default
  (`protect_kms_key`, `db_deletion_protection`). Turn them off first if you
  really want them removed.
- **WIF pools and providers are soft-deleted** and keep their IDs for 30
  days. Redeploying into the same project within that window needs a new
  `prefix`.
- Artifact Registry images, Cloud SQL backups and logs follow their own
  retention rules. Delete the project to be sure nothing is left.

## Known gaps

Blocking a working deployment today:

- No server container image or Dockerfile (step 3).
- No automated database migrations (step 5).
- The server's KMS public key variables are not set by Pulumi, so
  `carapace verify` fails without a manual step (step 5).
- CI publishes the enclave to ghcr.io, while the stack pulls both images
  from one `image_registry`; copying by digest is untested (step 3).

Not yet verified on real hardware, and fail closed if wrong unless noted
(details in [THREAT_MODEL.md](THREAT_MODEL.md#unverified-assumptions)):

- That the attestation token carries `submods.container.env.CONTROL_PLANE_URL`
  as the WIF condition expects. If not, nothing can decrypt.
- That the `image_digest` claim is the platform manifest digest.
- That the default Cloud Run URL format matches the one the stack computes.
- The `principalSubject` format of federated principals in KMS Data Access
  logs. If it differs, every enclave decrypt alerts (noisy, safe).
- That the KMS Data Access `methodName` is `AsymmetricDecrypt`. If it
  differs, unauthorized decrypts **do not alert**.
- That STS-federated credentials with `publicKeyViewer` can read the public
  key, and that a principal set keyed on a `sha256:` value works.
- That the launcher accepts the image's launch policy, including
  `log_redirect=always`, and that port 8443 is reachable.
- That the server service account and a non-confidential VM really get
  `PERMISSION_DENIED` from KMS.
- Provider details: `invoker_iam_disabled` on Cloud Run, the Cloud SQL
  edition and SSL mode combination, HSM availability in your region, and
  `on_host_maintenance = TERMINATE` on the Confidential VM.
