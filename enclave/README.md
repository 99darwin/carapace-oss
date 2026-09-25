# carapace-enclave

The code that runs inside the Confidential Space VM.

- `carapace_enclave.egress`: the generic credential-injecting executor. It
  validates an agent's HTTP request against a secret's injection policy,
  resolves DNS once and connects to the pinned public IP, injects the secret,
  and redacts it from the response.

Attestation, KMS unwrapping, the HTTP server, and receipts land in later PRs.

## Reproducible image

`enclave/Dockerfile` builds the image that runs in Confidential Space. The
KMS key is bound to the image digest, so anyone must be able to rebuild it
from a commit and get the same digest.

- **Build stage:** `python:3.13-slim-trixie`, pinned by digest. Third-party
  dependencies come from `requirements.lock` and are installed with
  `pip install --require-hashes --only-binary=:all: --no-deps --no-compile`.
  The lock is the `uv export` of `uv.lock` for this package only. A test
  fails if it drifts. First-party code is copied from an explicit include
  list, so the dev-only mock enclave can never reach the image. The build
  also fails if any `mock` path turns up under `carapace_enclave`.
- **Final stage:** `gcr.io/distroless/python3-debian13:nonroot`, pinned by
  digest. It has no shell and no package manager, and it runs as uid 65532.
  It needs no writable path, because no bytecode is shipped or written, so
  it runs with a read-only root filesystem.
- **Python 3.13 in both stages.** The build stage must match the runtime's
  CPython minor version so the compiled wheels load. The Debian 12
  distroless image ships Python 3.11, which is below this package's
  `requires-python`, so the image uses Debian 13 (Python 3.13).
- **Launch policy labels.** The launcher accepts only the `CONTROL_PLANE_URL`,
  `KMS_KEY_NAME` and `WIF_AUDIENCE` env overrides. It refuses command
  overrides and allows log redirect (`always`). A test keeps the override
  list equal to `ALLOWED_ENV_OVERRIDES` in
  `infra/pulumi/components/enclave_vm.py`.

The digest of record is the **linux/amd64 image manifest digest**. The
top-level index also holds the provenance and SBOM attestations. Those record
builder details, so they differ from one builder to the next.

### Rebuild and compare locally

Run these from the repository root. You need Docker and buildx with the
`docker-container` driver, which `rewrite-timestamp` requires. Use the
BuildKit version pinned in `.github/actions/build-enclave/action.yml`:

```bash
docker buildx create --name carapace-repro --driver docker-container \
  --driver-opt image=moby/buildkit:v0.33.0@sha256:6c2fa84a6b61ccd72899dde4239f8d5717f05f9a8ca6f3cad185fb1a95a94de3
docker buildx build --builder carapace-repro -f enclave/Dockerfile \
  --platform linux/amd64 --provenance=mode=max --sbom=true --no-cache \
  --build-arg SOURCE_DATE_EPOCH="$(git log -1 --format=%ct)" \
  --output type=oci,dest=enclave.tar,rewrite-timestamp=true .
python3 scripts/oci_image_digest.py enclave.tar
```

Compare the printed digest with the `digest` field in the signed
`releases/<tag>.json` attached to the GitHub release, and with the
`image_digest` claim in the enclave's attestation token.

### CI

`.github/workflows/enclave-image.yml` builds the image on `ubuntu-24.04` and
on `ubuntu-22.04` and fails if the two digests differ. On a `v*` tag it:

1. Refuses the tag unless its commit is already on the default branch, so
   a tag alone cannot release unreviewed code. Push `main` first, then the
   tag.
2. Refuses to proceed if the tag already has a release manifest naming a
   different image or commit. Release manifests are immutable; a moved tag
   fails before anything is pushed. Cut a new tag instead.
3. Builds a third time and pushes to `ghcr.io/<owner>/<repo>/enclave`.
4. Checks that the pushed digest equals the reproduced one.
5. Signs the image with keyless `cosign sign`.
6. Attaches `releases/<tag>.json` (`{tag, digest, commit, epoch}`) and its
   `cosign sign-blob` bundle to the release. `commit` is the tagged commit,
   also for annotated tags.

Both signatures are keyless and identify this workflow on a release tag.
Verify a manifest with:

```sh
cosign verify-blob \
  --bundle "releases/${TAG}.json.sigstore.json" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  --certificate-identity-regexp \
    '^https://github\.com/<owner>/<repo>/\.github/workflows/enclave-image\.yml@refs/tags/v' \
  "releases/${TAG}.json"
```

and the image with `cosign verify` and the same issuer and identity flags.
Check that the manifest's `tag` is the tag you asked for, so one release's
manifest cannot be served in place of another's.

The entrypoint is `python3 -m carapace_enclave`. The attested HTTPS server
(`carapace_enclave/__main__.py`) lands in a later PR. Until then the image
builds but exits at start.
