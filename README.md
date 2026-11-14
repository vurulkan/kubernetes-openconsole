# Kubernetes OpenConsole

A web console for several Kubernetes clusters. People see and operate the workloads their roles allow; every action
is audited. It runs inside Kubernetes, reads each cluster with one ServiceAccount, and decides every access in the app,
so users never get Kubernetes credentials. Scripts and AI agents use the same rules through a REST API with scoped
API keys.

**Documentation: <https://k8sopenconsole.github.io/>** (English · [Türkçe](https://k8sopenconsole.github.io/tr/)):
installation, user and admin guides, API and agents, operations, and reference lists generated from the code.

> New in 2.23.0: the manual moved from this README to the documentation site, now in English and Turkish.

![The OpenConsole Dashboard: the Pods tab with crash-looping and healthy pods](https://k8sopenconsole.github.io/img/screenshot-dark.png)

## Highlights

- **Access granted in the app**: users, groups and roles grant actions per cluster and namespace. Local, LDAP and
  Azure AD accounts. Namespaces you may not see stay hidden.
- **Every action audited**: reads and writes, sign-ins, denied calls; one structured event each, in the app and on
  stdout (ECS for Elastic). Pod shells are recorded and can be replayed.
- **Why a pod is failing**: status as `kubectl` prints it, the last exit code explained, the log before the restart,
  CPU and memory against limits, restart history; an overview and a node screen for admins.
- **Operate, when a role allows it**: restart and scale, YAML edit with diff and server dry-run, pod shell, secrets
  revealed one key at a time, logs of a pod, Deployment or Job.
- **Several clusters**: each user picks a cluster; permissions can be scoped per cluster.
- **API for scripts and agents**: API keys that never exceed their owner, OpenAPI 3.1 at `/api/openapi.json`, logs
  and one command over plain REST. Claude Code or Cursor work under the same rules as people.
- **Observability**: Prometheus `/metrics`, `/livez` and `/readyz`, OpenTelemetry tracing, JSON / ECS logs.
- English and Turkish UI, light and dark theme, keyboard first (`⌘K`, `?`).

The full list: [Features](https://k8sopenconsole.github.io/features).

## Quick start

```bash
docker run -d --name openconsole -p 8080:8080 \
  -v openconsole-data:/data \
  ghcr.io/vurulkan/kubernetes-openconsole:2.23.0
```

Open http://localhost:8080, sign in as `admin` / `admin` and choose a new password. Then add a cluster in
**Admin → Clusters** ([Connect a cluster](https://k8sopenconsole.github.io/installation/connect-cluster)): the
console never picks one up on its own.

For a team, [install it on Kubernetes](https://k8sopenconsole.github.io/installation/kubernetes) (kustomize, one
replica: the state is SQLite on a ReadWriteOnce volume). To look around without a cluster of your own,
[try it on k3d](https://k8sopenconsole.github.io/getting-started/try-on-k3d).

## Images

`ghcr.io/vurulkan/kubernetes-openconsole`, `linux/amd64` and `linux/arm64`, published only by this repository's CI.

| Tag | Points to |
|---|---|
| `X.Y.Z` (e.g. `2.23.0`) | that release; use this in production |
| `latest` | the newest release (same digest as its `X.Y.Z`) |
| `dev-<build>`, `dev-latest` | test builds of branches; never in production |

Every release has a signed build provenance and an SPDX SBOM (GitHub artifact attestations):

```bash
gh attestation verify oci://ghcr.io/vurulkan/kubernetes-openconsole:2.23.0 \
  --repo vurulkan/kubernetes-openconsole \
  --signer-workflow vurulkan/kubernetes-openconsole/.github/workflows/ci.yml
```

More in [Verify the image](https://k8sopenconsole.github.io/installation/verify-image).

## Documentation

| Section | |
|---|---|
| [Getting started](https://k8sopenconsole.github.io/intro) | what it is, quick start, try it on k3d, first login |
| [Installation](https://k8sopenconsole.github.io/installation/kubernetes) | Kubernetes, connect a cluster, upgrade, backup, uninstall, build from source |
| [User guide](https://k8sopenconsole.github.io/user-guide/signing-in) | Dashboard, pod health, logs, shell, YAML, secrets, API keys, shortcuts |
| [Administration](https://k8sopenconsole.github.io/administration/access-model) | access model, users, roles, LDAP, Azure AD, clusters, audit log, recordings, API access policy |
| [API and agents](https://k8sopenconsole.github.io/api/overview) | quick start, agent recipes, limits, every endpoint |
| [Operations](https://k8sopenconsole.github.io/operations/logging) | logging, Elastic, metrics and alerts, tracing, security model, hardening, air-gapped, troubleshooting |
| [Reference](https://k8sopenconsole.github.io/reference/environment-variables) | environment variables, permissions, audit events, metrics, Kubernetes permissions, shortcuts |
| [Release notes](https://k8sopenconsole.github.io/release-notes) | every release |

Older releases' manuals are their README at the release tag (for example
[v2.22.0](https://github.com/vurulkan/kubernetes-openconsole/blob/v2.22.0/README.md)).

## Development

Go backend (`backend/`, chi, client-go, SQLite) and React frontend (`frontend/`, Vite, Tailwind), one image.

```bash
cd backend  && go vet ./... && go test -race ./...
cd frontend && npx tsc --noEmit -p . && npm test && npm run build
docker build -t kubernetes-openconsole:local .
```

[`CLAUDE.md`](CLAUDE.md) maps the code and the rules for changes (also read by coding agents);
[Build from source](https://k8sopenconsole.github.io/installation/build-from-source) has more. The documentation site
is [k8sopenconsole/k8sopenconsole.github.io](https://github.com/k8sopenconsole/k8sopenconsole.github.io).

OpenConsole is an internal visibility and operations platform, **not** a Kubernetes security boundary
([Security model](https://k8sopenconsole.github.io/operations/security)).
