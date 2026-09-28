# Self-hosting on GCP

This guide deploys Carapace into a GCP project you own, using the Pulumi
program in [`infra/pulumi`](../infra/pulumi/README.md). When you self-host,
you are the operator and the GCP project owner, so the server and project
risks in [THREAT_MODEL.md](THREAT_MODEL.md) are risks from yourself (and
anyone you give access to the project).

> **Status: pre-alpha.** The stack has run end to end once against a real
> project, through `carapace deploy --build`. What is unverified is listed
> in [Known gaps](#known-gaps). Do not put real secrets into a self-hosted
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
  two Secret Manager secrets (database URL, JWT secret). **The database
  instance has a public IPv4 address.** It has no authorized networks and
  requires TLS (`ssl_mode = ENCRYPTED_ONLY`), so only Cloud SQL connector
  clients holding `roles/cloudsql.client` (the Cloud Run service, and you
  through the Cloud SQL Auth Proxy) can open a connection, but the
  instance is reachable from the internet and is not in a private VPC. The
  server is outside the trusted computing base; the database holds only
  ciphertext, hashes, signed objects and receipts.
- An Artifact Registry repository for your images.
- Data Access audit logs for KMS, and a log-based alert on changes to who
  can decrypt (see [THREAT_MODEL.md, R1](THREAT_MODEL.md#r1-a-gcp-project-owner-can-decrypt)).

The full list, and what is deliberately not created, is in the
[infra README](../infra/pulumi/README.md).

## Prerequisites

- A **new, dedicated GCP project** with billing enabled, and Owner on it.
  Anyone with Owner on the project (or on its folder or organization) can
  grant themselves decrypt, so keep that set small. Editor alone cannot,
  but anyone holding a Cloud KMS role there may.
- A region where Cloud KMS HSM keys and N2D Confidential VMs are both
  available (the example uses `us-central1`).
- `gcloud`, authenticated with `gcloud auth application-default login`.
- Pulumi CLI 3.x and Python 3.12. Any backend works; `pulumi login --local`
  keeps state on your machine. The state contains the generated database
  password and JWT secret as Pulumi secrets, so protect it.
- Docker with buildx, to build the images.
- `crane` and `cosign`, only if you deploy published images instead of
  building your own.
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
`ghcr.io/<owner>/<repo>/enclave@<digest>` into your registry by digest.
Cloud Run and the VM pull from `image_registry`, not from ghcr.io. See
[Copying a published image](#copying-a-published-image) below.

### Server

Build the server image from the repository root with
[`server/Dockerfile`](../server/Dockerfile) and push it:

```bash
docker buildx build -f server/Dockerfile --platform linux/amd64 \
  --output type=registry,name=<image_registry>/server:<version> .
docker buildx imagetools inspect <image_registry>/server:<version>
```

Note the `linux/amd64` manifest digest from the inspect output. The image
installs the hash-locked `server/requirements.lock`, runs as uid 65532 and
serves on `$PORT` (Cloud Run sets it). The server is outside the trusted
computing base, so this image does not need to be reproducible. It never
contains credentials: the database URL and JWT secret reach it only as
Secret Manager references at run time. The same image also runs the
database migrations (step 5).

On a `v*` tag on the default branch, CI publishes the server image to
`ghcr.io/<owner>/<repo>/server` and signs it with cosign, as it does for the
enclave.

### Copying a published image

Copy each published image into `image_registry` by its `linux/amd64`
manifest digest (the enclave's is in `releases/<tag>.json`), after checking
its cosign signature on ghcr.io; signatures are not copied. The commands
are in the [infra README](../infra/pulumi/README.md#images). `crane copy`
keeps the manifest bytes, so the digest you pin is the published one, and
the final `crane digest` checks fail if the registry serves anything else.
**Unverified:** this has not been run against Artifact Registry.

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

**Database migrations.** The stack creates a Cloud Run job,
`<prefix>-migrate` (the `migration_job` output), that runs
`alembic upgrade head` from the server image with exactly the server's
environment, so it reads the database URL from the same Secret Manager
secret. Whenever `server_image_digest` changes, `pulumi up` runs the job,
waits for it to succeed, and only then updates the Cloud Run service; a
failed migration fails the deploy and leaves the old revision serving. To
run it by hand:

```bash
gcloud run jobs execute <prefix>-migrate --region <region> --wait
```

Migrations run before the new revision takes traffic, so the old revision
serves against the new schema for a while. Keep each migration compatible
with the previous server release (expand, then contract in a later release).
The job ran and was waited for on a real deploy (2026-09-26, through
`carapace deploy`); a failed migration blocking the rollout has been tested
only with Pulumi mocks.

**KMS public key.** `pulumi up` reads the public key of key version 1 at
deploy time and sets `CARAPACE_KMS_PUBLIC_KEY_PEM` and
`CARAPACE_KMS_KEY_VERSION` (the `kms_key_version_name` output, the same
name the enclave gets as `KMS_KEY_NAME`) on the Cloud Run service, so
`GET /v1/kms/public-key` serves exactly the key the enclave reports. The
deployment fails, rather than shipping a mismatched pair, if KMS returns a
different version, a different algorithm, or no public key yet (the version
is not `ENABLED`; re-run). Whoever runs `pulumi up` needs
`cloudkms.cryptoKeyVersions.get` and `cloudkms.cryptoKeyVersions.viewPublicKey`
on the key; a project Owner has both. Both values are public. The server
refuses to start if only one of them is set.

## 6. First run: verify the enclave

Wait for the VM to boot and the enclave to register with the server (a few
minutes). Then, from your own machine:

```bash
carapace init
carapace signup --server "$(pulumi stack output server_url)" --email you@example.com
carapace verify --enclave "$(pulumi stack output enclave_url)" \
  --allow-digest sha256:<enclave digest> \
  --project-id "$(pulumi config get gcp:project)" \
  --service-account "$(pulumi stack output enclave_service_account)" \
  --kms-key "$(pulumi stack output kms_key_version_name)"
```

`verify` refuses an enclave in another project, running as another service
account, reporting to another server or using another KMS key (see
[VERIFY.md](VERIFY.md#what-it-checks)). Check that `image` is the digest you
built and allowed.

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

## Troubleshooting

### A zone has no capacity (stockout)

Google sometimes runs out of a machine type in one zone while the other
zones of the region still have it. Creating the enclave VM then fails
with something like:

```
Error waiting for instance to create: The zone
'projects/<project>/zones/us-central1-a' does not have enough resources
available to fulfill the request. Try a different zone, or try again
later. A n2d-standard-2 VM instance is currently unavailable in the
us-central1-a zone.
```

`carapace deploy` handles this when it is creating the VM (the stack's
state holds no VM yet). It asks Compute for the region's zones that are
`UP` and offer the enclave's machine type (read from
`infra/pulumi/components/config.py`, or `enclave_machine_type` in the
stack config), and runs the workloads step again in each of them in
order, printing one line per switch:

```
us-central1-a has no capacity for n2d-standard-2 now; trying us-central1-b.
```

The zone that worked becomes the deployment's: it is written to the
stack config (`gcp:zone`) and the deployment record, and later runs use
it. If every zone fails, the requested zone is kept and the error lists
the zones tried; run the same command again later, or deploy in another
region with a new `--prefix`. The fallback never leaves the region (the
key ring and the other regional resources cannot move) and never moves a
VM that is in the state. Pass `--no-zone-fallback` to report the stockout
and stop instead.

Only the enclave VM is zonal. While the state holds no VM, a re-run may
also pass another `--zone` of the same region by hand; once the VM
exists, a different `--zone` is refused, as is a different `--region`
at any time.

A new enclave image, or a newer Confidential Space image, replaces the
VM, deleting the old one first. If that create hits a stockout, the
state holds no VM, so the same run says the VM was deleted for its
replacement and creates the replacement in another zone (its static IP
is regional and kept, so the enclave URL does not change). A stockout
that leaves the VM in the state (a start after a stop for an update)
is reported as it is and moves nothing.

Note that the Confidential Space boot image is resolved from Google's
`confidential-space` family on every run, so a run made for any other
reason (say, a new server image) after Google publishes a new image
replaces the enclave VM, with the minutes of downtime that takes.

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

A deployment made with `carapace deploy` is removed with

```bash
carapace destroy --project <project> --prefix <prefix>
```

which prints the warnings below, asks you to type the project id, turns
off the deletion protection and runs `pulumi destroy`. It then removes the
empty Pulumi stack and, when they belong to this deployment, the session
and enclave pin in the CLI's config directory. The owner key is kept. A stack deployed
by hand is removed with

```bash
pulumi destroy
```

Things to know:

- **KMS key rings and keys cannot be deleted.** `pulumi destroy` schedules
  the key version for destruction (Google applies a waiting period, 30 days
  by default, before it is destroyed) and leaves the key ring name taken.
  Every secret sealed to that key becomes unrecoverable only once the
  version is actually destroyed. **During the waiting period anyone with
  `cloudkms.cryptoKeyVersions.restore` on the project (an Owner, or a KMS
  admin) can restore the version and grant themselves decrypt**, and by
  then `pulumi destroy` has already removed the audit-log configuration
  and the alert that would have flagged it. Treat every envelope stored in
  the database or its backups as decryptable by a project Owner until the
  version is destroyed. If the secrets matter, rotate the credentials they
  hold at their providers before tearing down, or delete the whole project
  (which also destroys its key versions after the same waiting period).
- The KMS key and database have deletion protection on by default
  (`protect_kms_key`, `db_deletion_protection`). Turn them off first if you
  really want them removed (`carapace destroy` does this for you).
- **WIF pools and providers are soft-deleted** and keep their IDs for 30
  days. Redeploying into the same project within that window needs a new
  `prefix`.
- Because of both, `carapace deploy` checks a new stack's prefix before
  its first `pulumi up`: if the key ring `<prefix>-keyring` or the pool
  `<prefix>-attest` exists (the pool in any state, deleted included), it
  refuses and names the leftover; pass another `--prefix`. It needs
  `cloudkms.keyRings.get` and `iam.workloadIdentityPools.get` (an Owner
  has both), and any error other than "not found" stops the deploy. A
  re-run of an existing deployment, or of a first run that failed after
  creating either, is not checked: its Pulumi state owns both names.
- Artifact Registry images, Cloud SQL backups and logs follow their own
  retention rules. Delete the project to be sure nothing is left.

## Known gaps

No gap is known to block a deployment. The stack has run end to end once,
through `carapace deploy --build`, on 2026-09-26; what that run checked is
listed in [THREAT_MODEL.md](THREAT_MODEL.md#verified-on-real-gcp).

Not yet verified on real hardware, and fail closed if wrong unless noted
(details in [THREAT_MODEL.md](THREAT_MODEL.md#unverified-assumptions)):

- That `crane copy` into Artifact Registry keeps the published digest
  (step 3). The CLI's own copy into Artifact Registry has run.
- The `principalSubject` format of federated principals in KMS Data Access
  logs. If it differs, every enclave decrypt alerts (noisy, safe).
- That the KMS Data Access `methodName` is `AsymmetricDecrypt`. If it
  differs, unauthorized decrypts **do not alert**.
- That STS-federated credentials with `publicKeyViewer` can read the public
  key.
- That the server service account and a non-confidential VM really get
  `PERMISSION_DENIED` from KMS.
- Provider details: `invoker_iam_disabled` on Cloud Run, the Cloud SQL
  edition and SSL mode combination, HSM availability in your region, and
  `on_host_maintenance = TERMINATE` on the Confidential VM.
