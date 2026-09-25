# No `# syntax=` line: the pinned BuildKit's built-in frontend parses this
# file, so no unpinned frontend image is pulled.
#
# Reproducible Carapace enclave image for GCP Confidential Space.
#
# Build from the repository root, never from enclave/:
#
#   docker buildx build -f enclave/Dockerfile --platform linux/amd64 \
#     --build-arg SOURCE_DATE_EPOCH="$(git log -1 --format=%ct)" \
#     --output type=oci,dest=enclave.tar,rewrite-timestamp=true .
#
# See enclave/README.md for the full reproduction steps. The digest of record
# is the linux/amd64 image manifest digest, not the index digest: the index
# also holds the provenance and SBOM attestations, which name the builder.
#
# Both stages run the same CPython minor version (3.13), so the compiled
# wheels installed in the build stage load in the final stage. The Debian 12
# distroless image ships Python 3.11, below the package's requires-python.

ARG BUILD_IMAGE=python:3.13-slim-trixie@sha256:8d9d0b8bcf6506481eae4907c18f5e3e7902e629f5f6d684f9e7c32e85e3ddf0
ARG RUNTIME_IMAGE=gcr.io/distroless/python3-debian13:nonroot@sha256:8ee214843129f43e2ebf5e0ca9f2e4e6d8292143d1b8a6787f169b5898578884

FROM ${BUILD_IMAGE} AS build

ARG SOURCE_DATE_EPOCH
ENV PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PYTHONDONTWRITEBYTECODE=1

# Third-party dependencies: exact versions, every artifact hash-checked,
# wheels only (no sdist builds), no .pyc files (bytecode is not reproducible
# and the root filesystem is read-only at runtime).
COPY enclave/requirements.lock /build/requirements.lock
RUN python -m pip install \
        --require-hashes \
        --only-binary=:all: \
        --no-deps \
        --no-compile \
        --target /app/site-packages \
        -r /build/requirements.lock \
    && rm -rf /app/site-packages/bin

# First-party code: an explicit include list. The dev-only mock enclave must
# never reach this image, so nothing here copies a whole source tree.
COPY enclave/src/carapace_enclave/__init__.py \
     enclave/src/carapace_enclave/py.typed \
     /app/site-packages/carapace_enclave/
COPY enclave/src/carapace_enclave/egress/ \
     /app/site-packages/carapace_enclave/egress/

# Fail the build if any mock code or bytecode slipped in, then normalise
# permissions so the result does not depend on the builder's umask.
RUN set -eu; \
    leaked="$(find /app/site-packages/carapace_enclave -iname '*mock*'; \
              find /app -name '__pycache__' -o -name '*.pyc')"; \
    if [ -n "$leaked" ]; then echo "forbidden paths in image: $leaked" >&2; exit 1; fi; \
    find /app -type d -exec chmod 0755 {} +; \
    find /app -type f -exec chmod 0644 {} +

FROM ${RUNTIME_IMAGE}

# Confidential Space launch policy. The launcher refuses any operator
# override not listed here. Keep allow_env_override identical to
# ALLOWED_ENV_OVERRIDES in infra/pulumi/components/enclave_vm.py (a test
# checks this). log_redirect=always lets the operator forward stdout/stderr
# to Cloud Logging; the enclave never logs secret material.
LABEL tee.launch_policy.allow_env_override="CONTROL_PLANE_URL,KMS_KEY_NAME,WIF_AUDIENCE" \
      tee.launch_policy.allow_cmd_override="false" \
      tee.launch_policy.log_redirect="always"

COPY --from=build /app /app

# Designed to run with a read-only root filesystem: nothing writes bytecode,
# and the working directory is never put on sys.path.
ENV PYTHONPATH=/app/site-packages \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONSAFEPATH=1 \
    PYTHONUNBUFFERED=1

USER 65532:65532
WORKDIR /app

# carapace_enclave.__main__ (the attested HTTPS server) lands with milestone 6.
ENTRYPOINT ["/usr/bin/python3", "-m", "carapace_enclave"]
