# No `# syntax=` line: the builder's built-in frontend parses this file, so
# no unpinned frontend image is pulled.
#
# Carapace control-plane server image (Cloud Run service and migration job).
#
# Build from the repository root, never from server/:
#
#   docker buildx build -f server/Dockerfile --platform linux/amd64 \
#     -t carapace-server .
#
# The server is untrusted by design, so unlike the enclave image nothing is
# bound to this image's digest. Infra still pins it by digest so a deploy
# runs exactly the image that was reviewed.
#
# Both stages run CPython 3.13, so the compiled wheels installed in the build
# stage load in the final stage. The images are the enclave's.
#
# There is no web UI yet; when web/ lands, its static build is added here.

ARG BUILD_IMAGE=python:3.13-slim-trixie@sha256:8d9d0b8bcf6506481eae4907c18f5e3e7902e629f5f6d684f9e7c32e85e3ddf0
ARG RUNTIME_IMAGE=gcr.io/distroless/python3-debian13:nonroot@sha256:8ee214843129f43e2ebf5e0ca9f2e4e6d8292143d1b8a6787f169b5898578884

FROM ${BUILD_IMAGE} AS build

ENV PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PYTHONDONTWRITEBYTECODE=1

# Third-party dependencies: exact versions, every artifact hash-checked,
# wheels only (no sdist builds), no .pyc files (the root filesystem can be
# read-only at runtime).
COPY server/requirements.lock /build/requirements.lock
RUN python -m pip install \
        --require-hashes \
        --only-binary=:all: \
        --no-deps \
        --no-compile \
        --target /app/site-packages \
        -r /build/requirements.lock \
    && rm -rf /app/site-packages/bin

# First-party code and the alembic migrations. Keep this list in step with
# server/Dockerfile.dockerignore (a test checks both).
COPY server/src/carapace_server/ \
     /app/site-packages/carapace_server/
COPY packages/crypto/src/carapace_crypto/ \
     /app/site-packages/carapace_crypto/
COPY server/alembic.ini /app/server/alembic.ini
COPY server/migrations/ /app/server/migrations/

# Fail the build if bytecode slipped in, then normalise permissions so the
# result does not depend on the builder's umask.
RUN set -eu; \
    leaked="$(find /app -name '__pycache__' -o -name '*.pyc')"; \
    if [ -n "$leaked" ]; then echo "forbidden paths in image: $leaked" >&2; exit 1; fi; \
    find /app -type d -exec chmod 0755 {} +; \
    find /app -type f -exec chmod 0644 {} +

FROM ${RUNTIME_IMAGE}

COPY --from=build /app /app

# No secrets here: the database URL and JWT secret reach the container only
# as Secret Manager references resolved by Cloud Run at start.
ENV PYTHONPATH=/app/site-packages \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONSAFEPATH=1 \
    PYTHONUNBUFFERED=1

# Cloud Run sets $PORT to the service's container port; the entrypoint reads
# it. Keep equal to DEFAULT_PORT (__main__.py) and CONTAINER_PORT (infra; a
# test checks all three).
EXPOSE 8080/tcp

USER 65532:65532
WORKDIR /app

# The migration job overrides this with
# `python3 -m alembic -c /app/server/alembic.ini upgrade head`.
ENTRYPOINT ["/usr/bin/python3", "-m", "carapace_server"]
