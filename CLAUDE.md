# Kubernetes OpenConsole — agent guide

Web console for several Kubernetes clusters: users see and operate workloads in the namespaces their
roles allow; every action is audited. One Go binary serves the API and the React build from a single
image; state is SQLite on a ReadWriteOnce volume (so **always 1 replica**). README.md is the user
manual (long, read only the section you need); this file is for working on the code.

## Map

`backend/` (Go, chi, client-go, slog, modernc sqlite) — entry point `cmd/server`.
| Path | What |
|---|---|
| `internal/api` | HTTP + WebSocket handlers. `router.go` holds the routes, `requirePermission`, most handlers; features split out (`workloads.go`, `deployment_actions.go`, `secrets.go`, `pod_exec.go`, `yaml_apply.go`, `clusters.go`, `views.go`, `exports.go`, …). `authz_test.go` = authorization suite |
| `internal/audit` | audit events: `Verb*` constants, `DetailKeys` registry (`event.go`), DB + console mirror (`logger.go`), 2.16 legacy upgrade (`legacy.go`). Handlers call `s.auditEvent` / `s.auditRead` / `s.auditReadDenied` (`api/audit_events.go`) |
| `internal/rbac` | permission engine (role → namespace / resource / action, cluster-scoped grants) |
| `internal/auth` | local passwords + policy, JWT sessions, LDAP, Azure AD |
| `internal/kube` | per-cluster client + informer cache (`Manager`, `Registry`), event bus, resource reads, apply, YAML prettify |
| `internal/store`, `internal/db` | SQLite store (users, roles, clusters, sessions, views, recordings settings) and migrations; credentials encrypted at rest |
| `internal/config` | env vars (`Load`), feature flags (`FEATURE_*`) |
| `internal/logging` | slog setup; `LOG_FORMAT=text|json|ecs` (`ecs.go`) |
| `internal/recording` | pod shell session recording (asciicast), quota / eviction |
| `internal/telemetry`, `internal/version` | OpenTelemetry tracing; build version |
| `internal/testutil/ldapfake` | in-process LDAP server for tests |

`frontend/` (React 18, TypeScript, Vite, Tailwind, react-i18next, Monaco, xterm.js).
| Path | What |
|---|---|
| `src/pages/DashboardPage.tsx` | workloads screen (cards + table, tabs per kind); `pages/dashboard/ResourceListView.tsx` table columns |
| `src/pages/AdminPage.tsx` | admin shell + audit, clusters, LDAP, Azure; `pages/admin/*` users, groups, roles, sessions, recordings |
| `src/components` | `ui.tsx` (Button, Badge, …), `DataTable`, `Drawer`, `ConfirmDialog`, `Combobox`, modals, `CommandPalette`, `LiveEventsPanel` |
| `src/hooks` | global / scoped keyboard shortcuts, modal scopes |
| `src/services/api.ts` | every API call |
| `src/i18n.ts` | EN + TR dictionaries (one file) |
| `src/utils` | `formatAge`, `formatBytes`, `formatDuration` |

`deploy/`: kustomize manifests; `rbac.yaml` / `rbac-readonly.yaml` = ClusterRole of the token users paste in;
`elk/` = Elasticsearch ingest pipeline + mappings for the logs. `.github/workflows/ci.yml` = tests + image publish.

Large files (`AdminPage.tsx`, `router.go`, `DashboardPage.tsx`, `i18n.ts`, ~1500–2700 lines): grep for the
part you need and read that range. New screens and handlers go in their own files, not into these.

## Commands

Toolchain (go, node, npm, docker, kubectl, k3d) is in `/opt/homebrew/bin`, which may not be on PATH:
`export PATH=/opt/homebrew/bin:$PATH`. Shell is zsh: write `${IMG}:latest`, never `$IMG:latest` (`:l` is a modifier).

```bash
# same as CI; run before every commit
cd backend  && go vet ./... && go build ./... && go test -race ./...
cd frontend && npm ci && npx tsc --noEmit -p . && npm test && npm run build

# local dev: backend on :8080 (DB in backend/data/), Vite on :5173 proxies /api and /ws
cd backend  && go run ./cmd/server
cd frontend && npm run dev
```
First login `admin` / `admin`. No cluster is picked up automatically: add one in Admin → Clusters.

Smoke test before a PR: `docker build -t kubernetes-openconsole:local .`, run it, check `/healthz` + `/readyz`.
End to end: throwaway `k3d cluster create oc-smoke --kubeconfig-switch-context=false`, always use
`kubectl --context k3d-oc-smoke`, never touch other contexts, delete the cluster afterwards.
Don't pipe `go test` into grep in a chain that pushes: the pipe hides the failure.

## When you add …

- **an endpoint** → route in `router.go`, `requirePermission`, audit for success + denied + failed
  (reads: `auditRead` / `auditReadDenied`), a case in `authz_test.go`, `services/api.ts`.
- **an audit detail key** → `audit.DetailKeys` + `deploy/elk/openconsole@mappings.component-template.json`.
  Never write secret values, YAML bodies, passwords or tokens into audit or logs.
- **UI text** → key in both EN and TR in `i18n.ts` (the parity test fails otherwise).
- **an env var / feature flag** → `internal/config` + README "Environment variables" + `deploy/deployment.yaml` comment.
- **a Kubernetes API the app reads or writes** → `deploy/rbac.yaml` and `deploy/rbac-readonly.yaml`.
- **a DB column / table** → migration in `internal/db` (idempotent; store tests upgrade an old schema).
- **any UI** → light + dark theme, TR + EN, keyboard reachable, axe clean (frontend tests run axe).

## UI / UX

Designs follow the project design system, generated with
[ui-ux-pro-max-skill](https://github.com/nextlevelbuilder/ui-ux-pro-max-skill) ("real-time operations",
data-dense, status colors green / amber / red, dark + light). The design system and the per-milestone design
notes live in the milestones repo (below), `kubernetes-openconsole/DESIGN_SYSTEM.md`. For new screens use
the skill (`/plugin marketplace add nextlevelbuilder/ui-ux-pro-max-skill`, then
`/plugin install ui-ux-pro-max@ui-ux-pro-max-skill`) and keep to the existing Tailwind tokens and
`components/ui.tsx`; don't introduce a second component library.

## Release

Feature branch `X.Y.Z-name` → squash merge to `main` → `git tag -a vX.Y.Z` + push the tag → CI builds once
and publishes `ghcr.io/vurulkan/kubernetes-openconsole:X.Y.Z` and `:latest` (same digest, amd64 + arm64,
GitHub attestations) → check digests, `gh attestation verify`, smoke test → `gh release create`.
Pushes to `main` build and test but publish nothing. **Never `docker push` by hand**, never add `:<sha>` or
signature tags. The version comes from the tag (Dockerfile `ARG VERSION` → `internal/version`, `dev` locally).

## Planning

Milestones, decisions and status: <https://github.com/vurulkan/milestones> → `kubernetes-openconsole/`
(`README.md` index + standard steps, `STATUS.md`, `M*.md`). Check the current milestone before larger work.

Keep this file current: if you change the layout, a command or a rule above, update it in the same change.
