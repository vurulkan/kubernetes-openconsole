# syntax=docker/dockerfile:1

# The build stages run on the builder's own platform and cross-compile, so a
# multi-arch (amd64 + arm64) build needs no emulation for Go or npm.
# Base images are pinned by digest; bump the tag and the digest together
# (docker buildx imagetools inspect <image>:<tag>).
FROM --platform=$BUILDPLATFORM node:26-alpine@sha256:6bd9ab43c0ec0190ca7b2d193906cb8b7edf6e7f4afa43ddeccd6452710bffb5 AS frontend-build
WORKDIR /app
# npm ci installs exactly package-lock.json, the versions CI tested.
COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci
COPY frontend ./
RUN npm run build

FROM --platform=$BUILDPLATFORM golang:1.27.4-alpine@sha256:0a5f7fe796599ff487605987432e7619ae45beeb2fba4c2ce0b907879932aebf AS backend-build
ARG TARGETOS
ARG TARGETARCH
# Release builds pass the tag's version (CI: build-args VERSION=X.Y.Z).
ARG VERSION=dev
WORKDIR /app
COPY backend/go.mod backend/go.sum ./
RUN go mod download
COPY backend ./
ENV CGO_ENABLED=0
RUN GOOS=$TARGETOS GOARCH=$TARGETARCH go build \
      -ldflags "-X k8s-dashboard/backend/internal/version.Version=${VERSION}" \
      -o /app/server ./cmd/server \
  && mkdir -p /out/data

# Distroless: no shell, no package manager, no network tools; just the
# static binary, CA certificates and time zone data. Debug with
# `kubectl debug`; copy backups out as the docs' Backup page describes.
FROM gcr.io/distroless/static:nonroot@sha256:aafe993665bf6200db38a02c11a9351e782a84b6a45e7f33b6695638c88e3931 AS runtime
LABEL org.opencontainers.image.title="Kubernetes OpenConsole" \
      org.opencontainers.image.source="https://github.com/vurulkan/kubernetes-openconsole" \
      org.opencontainers.image.documentation="https://k8sopenconsole.github.io/" \
      org.opencontainers.image.licenses="Apache-2.0"
WORKDIR /app
# The image runs as 100:101, the user of the Alpine images up to 2.23.0, so a
# Docker volume made by them stays writable. (Kubernetes sets its own user,
# 65532, and fsGroup in deploy/deployment.yaml.) /data starts empty and owned
# by that user, so `docker run` with a fresh volume can write the DB.
COPY --from=backend-build --chown=100:101 /out/data /data
COPY --from=backend-build /app/server /app/server
COPY --from=frontend-build /app/dist /app/public
# Defaults match deploy/deployment.yaml, so `docker run` works without any
# env: SQLite + session recordings live under /data (mount a volume there).
ENV DATA_PATH=/data/app.db \
    STATIC_DIR=/app/public
VOLUME ["/data"]
USER 100:101
EXPOSE 8080
ENTRYPOINT ["/app/server"]
