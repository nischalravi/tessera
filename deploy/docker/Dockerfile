# syntax=docker/dockerfile:1.7
#
# Tessera images. Build from the repository root:
#
#   docker build -f deploy/docker/Dockerfile --target api    -t tessera-api    .
#   docker build -f deploy/docker/Dockerfile --target ui     -t tessera-ui     .
#   docker build -f deploy/docker/Dockerfile --target devidp -t tessera-devidp .   # development only
#   docker build -f deploy/docker/Dockerfile --target cli    -t tessera-cli    .
#
# Multi-arch: docker buildx build --platform linux/amd64,linux/arm64 ... (the Go stages cross-compile on
# the build host, so no QEMU is needed for them). Pin the base images by digest in your own registry
# mirror for fully reproducible builds (--build-arg GO_IMAGE=golang:1.27@sha256:...).
#
# The Go API does not serve the web UI: the `ui` image serves mvp/frontend/dist with nginx and proxies the
# API paths (see deploy/docker/nginx/) to the API, so one origin serves both (the UI is same-origin in prod).
# The dev IdP is its own target and is never part of the `api` image.

ARG GO_IMAGE=golang:1.27-bookworm
ARG NODE_IMAGE=node:24-bookworm-slim
ARG NGINX_IMAGE=nginxinc/nginx-unprivileged:1.27-alpine
ARG STATIC_IMAGE=gcr.io/distroless/static-debian12:nonroot

# ---------------------------------------------------------------- Go build
FROM --platform=$BUILDPLATFORM ${GO_IMAGE} AS gobuild
ARG TARGETOS
ARG TARGETARCH
WORKDIR /src
COPY mvp/server/go.mod mvp/server/go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod go mod download
COPY mvp/server/ ./
# SQLite is modernc.org/sqlite (pure Go): CGO off gives a static binary that runs on distroless/static.
ENV CGO_ENABLED=0 GOFLAGS=-trimpath
RUN --mount=type=cache,target=/go/pkg/mod --mount=type=cache,target=/root/.cache/go-build \
    for c in tessera tessera-cli tessera-devidp; do \
      GOOS=$TARGETOS GOARCH=$TARGETARCH go build -ldflags="-s -w -buildid=" -o /out/$c ./cmd/$c || exit 1; \
    done
# Empty, nonroot-owned directories for the final images (volumes are mounted over them).
RUN mkdir -p /rootfs/var/lib/tessera /rootfs/tmp && chmod 1777 /rootfs/tmp && chmod 0750 /rootfs/var/lib/tessera

# ---------------------------------------------------------------- UI build
FROM --platform=$BUILDPLATFORM ${NODE_IMAGE} AS uibuild
WORKDIR /ui
COPY mvp/frontend/package.json mvp/frontend/package-lock.json ./
RUN --mount=type=cache,target=/root/.npm npm ci --no-audit --no-fund
COPY mvp/frontend/ ./
RUN npm run build

# ---------------------------------------------------------------- common labels
FROM ${STATIC_IMAGE} AS base
ARG VERSION=dev
ARG REVISION=unknown
ARG CREATED=unknown
LABEL org.opencontainers.image.vendor="Tessera" \
      org.opencontainers.image.source="https://github.com/nischalravi/tessera" \
      org.opencontainers.image.licenses="see LICENSE" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${REVISION}" \
      org.opencontainers.image.created="${CREATED}"

# ---------------------------------------------------------------- API (production image)
# No shell and no curl in distroless, so there is no HEALTHCHECK instruction: orchestrators probe
# GET /api/health on the API port (Kubernetes probes, ALB/Cloud Run/Container Apps health checks, Compose
# healthcheck through the ui image's wget).
FROM base AS api
LABEL org.opencontainers.image.title="tessera-api" \
      org.opencontainers.image.description="Tessera API (tessera serve|worker|admin|backup|...)"
COPY --from=gobuild --chown=65532:65532 /rootfs/ /
COPY --from=gobuild /out/tessera /usr/local/bin/tessera
USER 65532:65532
WORKDIR /var/lib/tessera
VOLUME ["/var/lib/tessera"]
EXPOSE 8000
# Containers must listen on all interfaces; production refuses the dev defaults (mvp/README.md, Server hardening).
ENV TESSERA_ENV=prod
ENTRYPOINT ["/usr/local/bin/tessera"]
CMD ["serve", "-addr", "0.0.0.0:8000"]

# ---------------------------------------------------------------- operator CLI
FROM base AS cli
LABEL org.opencontainers.image.title="tessera-cli"
COPY --from=gobuild --chown=65532:65532 /rootfs/ /
COPY --from=gobuild /out/tessera-cli /usr/local/bin/tessera-cli
USER 65532:65532
WORKDIR /var/lib/tessera
ENV TESSERA_CONFIG_DIR=/var/lib/tessera/cli
ENTRYPOINT ["/usr/local/bin/tessera-cli"]

# ---------------------------------------------------------------- dev IdP (development and tests only)
FROM base AS devidp
LABEL org.opencontainers.image.title="tessera-devidp" \
      org.opencontainers.image.description="Mock OIDC issuer for local sign-in. NEVER deploy to production."
COPY --from=gobuild --chown=65532:65532 /rootfs/ /
COPY --from=gobuild /out/tessera-devidp /usr/local/bin/tessera-devidp
USER 65532:65532
WORKDIR /var/lib/tessera
EXPOSE 8001
# The dev IdP refuses non-loopback listen addresses: reach it from another container by sharing its network
# namespace (docker run --network container:<name>), or run it as a pod sidecar. It needs TESSERA_ENV=dev or test.
ENV TESSERA_ENV=dev
ENTRYPOINT ["/usr/local/bin/tessera-devidp"]

# ---------------------------------------------------------------- UI (nginx, unprivileged, uid 101)
FROM ${NGINX_IMAGE} AS ui
ARG VERSION=dev
ARG REVISION=unknown
ARG CREATED=unknown
LABEL org.opencontainers.image.title="tessera-ui" \
      org.opencontainers.image.description="Tessera web UI (static) with a reverse proxy to the API" \
      org.opencontainers.image.vendor="Tessera" \
      org.opencontainers.image.source="https://github.com/nischalravi/tessera" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${REVISION}" \
      org.opencontainers.image.created="${CREATED}"
COPY deploy/docker/nginx/nginx.conf /etc/nginx/nginx.conf
COPY deploy/docker/nginx/tessera.conf.template /etc/nginx/templates/tessera.conf.template
COPY deploy/docker/nginx/tessera-proxy.inc /etc/nginx/tessera-proxy.inc
COPY --from=uibuild /ui/dist /usr/share/nginx/html
# Only /tmp needs to be writable (rendered config, pid, temp files): run with a read-only root filesystem
# and a tmpfs or emptyDir on /tmp.
ENV API_UPSTREAM=api:8000 \
    NGINX_ENVSUBST_OUTPUT_DIR=/tmp/nginx-conf
EXPOSE 8080
HEALTHCHECK --interval=15s --timeout=3s --start-period=10s --retries=3 \
  CMD wget -q -O /dev/null http://127.0.0.1:8080/healthz || exit 1
