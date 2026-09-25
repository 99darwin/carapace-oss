# Carapace infrastructure (GCP, Pulumi)

One Pulumi program that deploys a self-hosted Carapace, with key release gated
by attestation. The same program serves any deployment. Stacks differ only in
their config.

## What it creates

| Component | Resources |
|---|---|
| `apis.py` | Enables the Compute, Cloud KMS, Confidential Computing, IAM, IAM Credentials, STS, Cloud Run, Cloud SQL Admin, Artifact Registry, Logging, Secret Manager and Monitoring APIs |
| `kms.py` | One key ring and one `ASYMMETRIC_DECRYPT` / `RSA_DECRYPT_OAEP_4096_SHA256` / `HSM` key (`protect` is on by default), plus an **authoritative** IAM policy on the key |
| `wif.py` | A Workload Identity pool and an OIDC provider that trust Confidential Space attestation tokens |
| `identity.py` | Enclave VM service account and server (Cloud Run) service account |
| `enclave_vm.py` | A dedicated VPC and subnet, one static external IP, one firewall rule (tcp:443 ingress), and one Confidential Space VM (AMD SEV, Secure Boot) |
| `server.py` | An Artifact Registry repo, Cloud SQL Postgres 16 (`db-f1-micro`, zonal), a generated DB password in Secret Manager, and a Cloud Run v2 service (min 0 instances) |
| `monitoring.py` | Optional. A log-match alert on IAM or configuration changes to the KMS key, the WIF pool, or project IAM |

### Who can decrypt

The key's IAM policy is authoritative, so each `pulumi up` removes any binding
added by hand. It contains exactly:

- `roles/cloudkms.cryptoKeyDecrypter`: one WIF `principalSet` per entry in
  `allowed_digests`:
  `principalSet://iam.googleapis.com/projects/<number>/locations/global/workloadIdentityPools/<prefix>-attest/attribute.image_digest/<digest>`
- `roles/cloudkms.publicKeyViewer`: the server service account.

The WIF provider accepts a token only if **all** of the following hold:

```
assertion.swname == 'CONFIDENTIAL_SPACE'
assertion.hwmodel == 'GCP_AMD_SEV'
assertion.dbgstat == 'disabled-since-boot'
assertion.secboot == true
'STABLE' in assertion.submods.confidential_space.support_attributes
assertion.submods.container.image_digest in [<allowed_digests>]
assertion.submods.gce.project_id == '<this project>'
'<enclave SA email>' in assertion.google_service_accounts
```

The last two clauses pin the token to this project's VM. The enclave image is
public, so without them anyone could run the same image in their own project
and present a valid token.

The enclave VM's service account has only `logging.logWriter`,
`artifactregistry.reader` and `confidentialcomputing.workloadUser`. It has **no
KMS role**, and the enclave never falls back to ambient credentials. The server
service account has only `publicKeyViewer` on the key, `cloudsql.client`, and
`secretAccessor` on the DB password secret.

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

The outputs include `enclave_url`, `server_url`, `kms_key_version_name` and
`wif_provider_name`. `carapace verify` checks the enclave against these values.

### Config keys

| Key | Default | Notes |
|---|---|---|
| `gcp:project` | required | |
| `gcp:region` / `gcp:zone` | `us-central1` / `<region>-a` | Pick a zone that offers N2D Confidential VMs |
| `prefix` | `carapace` | 3–20 chars. Every resource name is derived from it |
| `allowed_digests` | required | List of `sha256:…`. Each digest gets one decrypter binding |
| `enclave_image_digest` | required* | Must appear in `allowed_digests`. Tags are refused |
| `server_image_digest` | required* | Tags are refused |
| `image_registry` | this stack's AR repo | Images are `<registry>/enclave@…` and `<registry>/server@…` |
| `deploy_workloads` | `true` | `false` skips the VM and Cloud Run (*digests are then optional) |
| `control_plane_url` | Cloud Run URL | Passed to the enclave as `CONTROL_PLANE_URL` |
| `wif_audience` | `https://sts.googleapis.com` | Allowed audience on the WIF provider |
| `enclave_machine_type` | `n2d-standard-2` | Must support AMD SEV |
| `db_tier` | `db-f1-micro` | |
| `server_min_instances` / `server_max_instances` | `0` / `2` | |
| `protect_kms_key` | `true` | Pulumi `protect` on the key ring and key |
| `db_deletion_protection` | `true` | |
| `enable_iam_alerts` / `alert_emails` | `false` / `[]` | Alert on changes to the decrypt path |

### Rolling out a new enclave image

1. Add the new digest to `allowed_digests` and run `pulumi up`. Both digests
   can now decrypt.
2. Set `enclave_image_digest` to the new digest and run `pulumi up`. The
   Confidential Space launcher reads metadata only at boot, so Pulumi deletes
   the VM and recreates it on the new image. Expect a few minutes of enclave
   downtime.
3. Remove the old digest from `allowed_digests` and run `pulumi up`.

The enclave receives exactly two environment overrides, `CONTROL_PLANE_URL`
and `KMS_KEY_NAME` (the key **version** resource name). The image's launch
policy must allow these two and nothing else.

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

## Residual risk

A project owner can still change IAM on the key or loosen the WIF condition.
Such changes appear in Cloud Audit Logs (Admin Activity, always on). Set
`enable_iam_alerts` to get an alert within minutes. For self-hosters, the
project owner is you.

## Tests

The tests use Pulumi mocks and never touch GCP:

```bash
uv venv venv && VIRTUAL_ENV=venv uv pip install -r requirements-dev.txt
venv/bin/pytest && venv/bin/ruff check . && venv/bin/ruff format --check .
```
