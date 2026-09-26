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
# Three stages: `web` builds the single-page UI, `build` installs the Python
# dependencies and collects everything under /app, and the runtime stage
# copies /app alone. Both Python stages run CPython 3.13, so the compiled
# wheels installed in the build stage load in the final stage. The images
# are the enclave's; the node image is only ever a build stage.

ARG WEB_BUILD_IMAGE=node:24-trixie-slim@sha256:8ec5d7557396cfe32d21c3f9c13072355ceab22b584578ca4bb28af31120cffe
ARG BUILD_IMAGE=python:3.13-slim-trixie@sha256:8d9d0b8bcf6506481eae4907c18f5e3e7902e629f5f6d684f9e7c32e85e3ddf0
ARG RUNTIME_IMAGE=gcr.io/distroless/python3-debian13:nonroot@sha256:8ee214843129f43e2ebf5e0ca9f2e4e6d8292143d1b8a6787f169b5898578884

FROM ${WEB_BUILD_IMAGE} AS web

ENV CI=1 \
    NPM_CONFIG_AUDIT=false \
    NPM_CONFIG_FUND=false \
    NPM_CONFIG_UPDATE_NOTIFIER=false

WORKDIR /web

# Exact versions and integrity hashes from the lockfile (`npm ci` refuses a
# lockfile that disagrees with package.json). Lifecycle scripts are off:
# nothing the build needs runs one (the only package in the lock with an
# install script is fsevents, which is macOS-only), so no dependency gets to
# execute code at install time.
COPY web/package.json web/package-lock.json ./
RUN npm ci --ignore-scripts

# Only what the build reads; tests and the e2e harness stay out (see
# server/Dockerfile.dockerignore).
COPY web/index.html web/tsconfig.json web/vite.config.ts ./
COPY web/public/ public/
COPY web/src/ src/
RUN npm run build

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

# The built UI, served at / by the server (CARAPACE_WEB_DIR below). Only the
# build output crosses over: no node_modules, sources or lockfile.
COPY --from=web /web/dist/ /app/web/

# Fail the build if bytecode slipped in or the UI build is empty, then
# normalise permissions so the result does not depend on the builder's
# umask.
RUN set -eu; \
    leaked="$(find /app -name '__pycache__' -o -name '*.pyc')"; \
    if [ -n "$leaked" ]; then echo "forbidden paths in image: $leaked" >&2; exit 1; fi; \
    if [ ! -f /app/web/index.html ]; then echo "web build produced no index.html" >&2; exit 1; fi; \
    find /app -type d -exec chmod 0755 {} +; \
    find /app -type f -exec chmod 0644 {} +

FROM ${RUNTIME_IMAGE}

COPY --from=build /app /app

# No secrets here: the database URL and JWT secret reach the container only
# as Secret Manager references resolved by Cloud Run at start.
ENV PYTHONPATH=/app/site-packages \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONSAFEPATH=1 \
    PYTHONUNBUFFERED=1 \
    CARAPACE_WEB_DIR=/app/web

# Cloud Run sets $PORT to the service's container port; the entrypoint reads
# it. Keep equal to DEFAULT_PORT (__main__.py) and CONTAINER_PORT (infra; a
# test checks all three).
EXPOSE 8080/tcp

USER 65532:65532
WORKDIR /app

# The migration job overrides this with
# `python3 -m alembic -c /app/server/alembic.ini upgrade head`.
ENTRYPOINT ["/usr/bin/python3", "-m", "carapace_server"]
