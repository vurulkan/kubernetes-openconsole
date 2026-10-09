# syntax=docker/dockerfile:1

FROM node:20-alpine AS frontend-build
WORKDIR /app
COPY frontend/package.json ./
RUN npm install
COPY frontend ./
RUN npm run build

FROM golang:1.21-alpine AS backend-build
WORKDIR /app
COPY backend/go.mod ./
COPY backend ./
ENV CGO_ENABLED=0
RUN go build -o /app/server ./cmd/server

FROM alpine:3.19 AS runtime
RUN apk add --no-cache ca-certificates iputils bind-tools busybox-extras \
  && addgroup -S appgroup \
  && adduser -S appuser -G appgroup \
  && mkdir -p /data \
  && chown appuser:appgroup /data
WORKDIR /app
COPY --from=backend-build /app/server /app/server
COPY --from=frontend-build /app/dist /app/public
# Defaults match deploy/deployment.yaml, so `docker run` works without any
# env: SQLite + session recordings live under /data (mount a volume there).
ENV DATA_PATH=/data/app.db \
    STATIC_DIR=/app/public
VOLUME ["/data"]
USER appuser
EXPOSE 8080
ENTRYPOINT ["/app/server"]
