# Carapace infrastructure (GCP, Pulumi)

One Pulumi program that deploys a self-hosted Carapace, with key release gated
by attestation. The same program serves any deployment. Stacks differ only in
their config.

## What it creates

| Component | Resources |
|---|---|
| `apis.py` | Enables the Compute, Cloud KMS, Confidential Computing, IAM, IAM Credentials, STS, Cloud Run, Cloud SQL Admin, Artifact Registry, Logging, Secret Manager and Monitoring APIs |
| `kms.py` | One key ring and one `ASYMMETRIC_DECRYPT` / `RSA_DECRYPT_OAEP_4096_SHA256` / `HSM` key (`protect` is on by default), an **authoritative** IAM policy on the key, and Data Access (`DATA_READ`) audit logs for Cloud KMS so every decrypt is logged |
| `wif.py` | A Workload Identity pool and an OIDC provider that trust Confidential Space attestation tokens |
| `identity.py` | Enclave VM service account and server (Cloud Run) service account |
| `enclave_vm.py` | A dedicated VPC and subnet, one static external IP, one firewall rule (tcp:443 ingress), and one Confidential Space VM (AMD SEV, Secure Boot) |
| `server.py` | An Artifact Registry repo, Cloud SQL Postgres 16 (`db-f1-micro`, zonal), two generated secrets in Secret Manager (the database URL and the JWT signing secret), and a Cloud Run v2 service (min 0 instances) |
| `monitoring.py` | On by default. A log-match alert on IAM or configuration changes to the KMS key ring and key, the WIF pool, the enclave service account, or project IAM, and on any `AsymmetricDecrypt` by a principal outside the attestation pool |

### Who can decrypt

The key's IAM policy is authoritative, so each `pulumi up` removes any binding
added by hand. It contains exactly:

- `roles/cloudkms.cryptoKeyDecrypter`: one WIF `principalSet` per entry in
  `allowed_digests`:
  `principalSet://iam.googleapis.com/projects/<number>/locations/global/workloadIdentityPools/<prefix>-attest/attribute.image_digest/<digest>`
- `roles/cloudkms.publicKeyViewer`: the server service account.

The key ring also has an authoritative IAM policy, and that policy has **zero**
bindings. Ring-level grants would be inherited by the key, so `pulumi up`
removes any that are added by hand.

### Two audiences

The enclave publishes Confidential Space tokens through `GET /attestation`,
so a token it hands to clients must never be exchangeable at STS. Two
audiences keep the two uses apart:

- **STS audience.** The default is the provider's full resource name,
  `//iam.googleapis.com/projects/<number>/locations/global/workloadIdentityPools/<prefix>-attest/providers/confidential-space`.
  It is the **only** entry in the provider's `allowedAudiences`, and the CEL
  condition requires it as well. The stack exports it as `wif_audience`
  and passes it to the enclave as `WIF_AUDIENCE`. The enclave requests a
  token with this audience only for the STS exchange and never publishes it.
- **Client audience.** `carapace-attestation` is used only for the token
  served by `/attestation`. WIF does not accept it.

`wif_audience` can be overridden with any other stack-specific string. The
stack refuses `https://sts.googleapis.com`, the audience of the token the
launcher writes into the container by default, and it refuses
`carapace-attestation`. It also refuses the control plane URL: that is the
audience of the bearer tokens the enclave sends to the untrusted server,
which must never be exchangeable at STS.

The WIF provider accepts a token only if **all** of the following hold:

```
assertion.aud == '<STS audience>'
assertion.swname == 'CONFIDENTIAL_SPACE'
assertion.hwmodel == 'GCP_AMD_SEV'
assertion.dbgstat == 'disabled-since-boot'
assertion.secboot == true
'STABLE' in assertion.submods.confidential_space.support_attributes
assertion.submods.container.image_digest in [<allowed_digests>]
assertion.submods.gce.project_id == '<this project>'
'<enclave SA email>' in assertion.google_service_accounts
assertion.submods.container.env.CONTROL_PLANE_URL == '<control_plane_url>'
```

The `project_id` and service account clauses pin the token to this project's
VM. The enclave image is public, so without them anyone could run the same
image in their own project and present a valid token. The `CONTROL_PLANE_URL`
clause refuses a VM of this project that was launched with a different control
plane, since that override is one the launch policy allows.

`hwmodel == GCP_AMD_SEV` means the VM is an AMD SEV Confidential VM. SEV
encrypts guest memory, but it does **not** provide SNP's integrity protection
or SNP hardware attestation reports. The Confidential Space token is rooted in
the VM's vTPM measured boot, which Google attests. The trusted computing base
therefore includes AMD SEV, Google's vTPM and Shielded VM firmware, and the
Confidential Space image. This stack does not use SEV-SNP (see
[Open questions](#open-questions)).

The enclave VM's service account has only `logging.logWriter` and
`confidentialcomputing.workloadUser` on the project, and
`artifactregistry.reader` on this stack's repository only. It has **no KMS
role**, and the enclave never falls back to ambient credentials. The server
service account has only `publicKeyViewer` on the key, `cloudsql.client` on
the project, and `secretAccessor` on its two secrets (not on the project).
`cloudsql.client` stays project-level because Cloud SQL has no instance-level
IAM, only IAM conditions; the database password is still required to connect.

### Server environment

The server reads `CARAPACE_*` variables and silently ignores anything else, so
`tests/test_server_env_contract.py` checks the names below against
`server/src/carapace_server/config.py`:

| Variable | Source |
|---|---|
| `CARAPACE_MODE` | `prod` |
| `CARAPACE_PUBLIC_URL` | `control_plane_url` |
| `CARAPACE_ALLOWED_IMAGE_DIGESTS` | `allowed_digests`, comma-separated |
| `CARAPACE_ATTESTATION_PROJECT_ID` | `gcp:project` |
| `CARAPACE_ATTESTATION_SERVICE_ACCOUNT` | the enclave service account |
| `CARAPACE_DATABASE_URL` | Secret Manager `<prefix>-database-url` (`postgresql+asyncpg` over the `/cloudsql` socket, generated password) |
| `CARAPACE_JWT_SECRET` | Secret Manager `<prefix>-jwt-secret` (64 random characters) |

Secret values are referenced by Cloud Run and never appear in plain env or
stack outputs. They are in Pulumi state, encrypted as Pulumi secrets.

No `serviceAccountUser`, `workloadIdentityUser` or `serviceAccountTokenCreator`
binding is created. Whoever runs `pulumi up` needs `iam.serviceAccounts.actAs`
on the two service accounts to attach them to the VM and to Cloud Run. A
project owner already has it.

## Prerequisites

- A GCP project with billing enabled, and Owner on it (or equivalent roles).
- `gcloud auth application-default login`.
- Pulumi CLI 3.x and Python 3.12. Any Pulumi backend works:
  `pulumi login --local` keeps state on your machine.
- Enclave and server images **pinned by digest**. Use a published release, or
  build your own and push it to the Artifact Registry repo this stack creates.

## Deploy

```bash
cd infra/pulumi
python3.12 -m venv venv && venv/bin/pip install -r requirements.txt
pulumi stack init mystack
cp Pulumi.example.yaml Pulumi.mystack.yaml   # then replace the placeholders
pulumi up
```

If you build your own images, bootstrap first without the workloads, then push
the images, set their digests, and deploy again:

```bash
pulumi config set deploy_workloads false && pulumi up
# push <image_registry>/enclave and /server, then:
pulumi config set deploy_workloads true && pulumi up
```

The outputs include `enclave_url`, `server_url`, `control_plane_url`,
`kms_key_version_name`, `wif_provider_name` and `wif_audience`, plus the
Secret Manager ids `database_url_secret` and `jwt_secret` (never the values).
`carapace verify` checks the enclave against these values.

### Config keys

| Key | Default | Notes |
|---|---|---|
| `gcp:project` | required | |
| `gcp:region` / `gcp:zone` | `us-central1` / `<region>-a` | Pick a zone that offers N2D Confidential VMs |
| `prefix` | `carapace` | 3–20 chars. Every resource name is derived from it. Use a new prefix to redeploy after a destroy (see below) |
| `allowed_digests` | required | List of `sha256:…`. Each digest gets one decrypter binding |
| `enclave_image_digest` | required* | Must appear in `allowed_digests`. Tags are refused |
| `server_image_digest` | required* | Tags are refused |
| `image_registry` | this stack's AR repo | Images are `<registry>/enclave@…` and `<registry>/server@…` |
| `deploy_workloads` | `true` | `false` skips the VM and Cloud Run (*digests are then optional) |
| `control_plane_url` | `https://<prefix>-server-<project number>.<region>.run.app` | A bare `https://host[:port]` origin (no path or trailing slash). Used as the server's `CARAPACE_PUBLIC_URL`, the enclave's `CONTROL_PLANE_URL`, and in the WIF condition |
| `wif_audience` | provider resource name | The only audience WIF accepts. Must be stack-specific. `https://sts.googleapis.com`, `carapace-attestation` and the control plane URL are refused |
| `enclave_machine_type` | `n2d-standard-2` | Must support AMD SEV |
| `db_tier` | `db-f1-micro` | |
| `server_min_instances` / `server_max_instances` | `0` / `2` | |
| `protect_kms_key` | `true` | Pulumi `protect` on the key ring and key |
| `db_deletion_protection` | `true` | |
| `enable_iam_alerts` / `alert_emails` | `true` / required | Alert on changes to the decrypt path. Set `enable_iam_alerts: "false"` to deploy without recipients |

### Rolling out a new enclave image

1. Add the new digest to `allowed_digests` and run `pulumi up`. Both digests
   can now decrypt.
2. Set `enclave_image_digest` to the new digest and run `pulumi up`. The
   Confidential Space launcher reads metadata only at boot, so Pulumi deletes
   the VM and recreates it on the new image. Expect a few minutes of enclave
   downtime.
3. Remove the old digest from `allowed_digests` and run `pulumi up`.

The enclave receives exactly three environment overrides:
`CONTROL_PLANE_URL`, `KMS_KEY_NAME` (the key **version** resource name) and
`WIF_AUDIENCE` (the STS audience). The image's launch policy must allow these
three and nothing else.

The VM also sets `tee-container-log-redirect=true`. This sends the
container's stdout and stderr to Cloud Logging, and it is the only reason the
VM service account holds `logging.logWriter`. The image's launch policy must
allow log redirect. The enclave never logs secrets, and its logs go to the
self-hoster's own project.

### Confidential Space image support

The boot disk is resolved from the latest image in the
`confidential-space` family of `confidential-space-images` each time
`pulumi up` runs. The WIF condition requires the `STABLE` support attribute.
Google publishes new images regularly and ends support for old ones; an image
that has aged out carries only `USABLE`, or nothing. Google does not publish a
fixed cadence. A VM keeps running its boot image, so a long-lived VM
eventually stops being able to decrypt. Run `pulumi up` periodically (monthly
is a reasonable interval). When the family has moved on, the image change
recreates the VM on the current image, which costs a few minutes of enclave
downtime.

### Destroy and redeploy

- KMS key rings and keys can't be deleted. `pulumi destroy` only schedules
  the key version for destruction and leaves the key ring name taken.
- WIF pools and providers are soft-deleted and keep their IDs for 30 days.

A redeploy into the same project within that window therefore needs a new
`prefix`.

## Cost estimate (us-central1, list prices)

| Item | ~USD/month |
|---|---|
| n2d-standard-2 Confidential VM, 24/7 | 62 |
| Static external IP (in use) | 4 |
| Cloud SQL `db-f1-micro` + 10 GB | 10 |
| KMS HSM key version (RSA 4096) | 3 |
| Cloud Run (min 0), Artifact Registry, Secret Manager, Logging | ~1 |
| **Total** | **~80** |

Stopping the VM when idle brings this to about $40/month. The IP and the
database still bill while the VM is stopped.

## What this does NOT create

- No Cloud NAT, VPC connector, Memorystore, Redis, or Celery/worker VMs.
- No DNS zones, custom domains, managed certificates, or load balancer. The
  enclave serves attested TLS on its IP; add a domain for the server
  yourself if you want one.
- No SSH or other ingress besides tcp:443 to the enclave.
- No Workload Identity pool for CI (GitHub Actions) deploys.
- No budget alerts, org policies, or VPC Service Controls.
- No idle-stop scheduler for the VM.
- No backups beyond Cloud SQL's default automated backups.
- No private IP for Cloud SQL. The instance has a public IP but **no
  authorized networks**, so it accepts only connections through the Cloud SQL
  Auth Proxy or connectors, which require IAM (`cloudsql.client`). This is an
  accepted trade-off: it avoids private services access and a VPC connector,
  and the database holds only envelope ciphertext.

## Residual risk

A project owner can still change IAM on the key or loosen the WIF condition.
Such changes appear in Cloud Audit Logs (Admin Activity, always on), and the
alert (on by default) fires within minutes. Every decrypt is also a Data
Access entry, so a decrypt by anyone other than the attested enclave alerts
too. Turning those logs off is itself a project `SetIamPolicy` change, which
alerts. For self-hosters, the project owner is you.

## Open questions

- **SEV-SNP.** Google's Confidential Space token claims reference does not
  yet list an `hwmodel` value for SEV-SNP. Once one is confirmed, add an option that sets `confidentialInstanceType = SEV_SNP` and
  requires that `hwmodel` in the WIF condition.

## Tests

The tests use Pulumi mocks and never touch GCP:

```bash
uv venv venv && VIRTUAL_ENV=venv uv pip install -r requirements-dev.txt
venv/bin/pytest && venv/bin/ruff check . && venv/bin/ruff format --check .
```
