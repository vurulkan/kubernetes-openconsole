# OpenConsole for Kubernetes — agent guide

Web console for several Kubernetes clusters: users see and operate workloads in the namespaces their
roles allow; every action is audited. One Go binary serves the API and the React build from a single
image; state is SQLite on a ReadWriteOnce volume (so **always 1 replica**). The user manual is the docs
site, <https://k8sopenconsole.github.io/>, source in [k8sopenconsole/k8sopenconsole.github.io](https://github.com/k8sopenconsole/k8sopenconsole.github.io)
(its own `CLAUDE.md`), English and Turkish. README.md is a short front door that links there. This file is for
working on the code.

## Map

`backend/` (Go, chi, client-go, slog, modernc sqlite) — entry point `cmd/server`; `cmd/docgen` writes the docs site's
reference pages into `docs/reference/` (see "Generated reference" below).
| Path | What |
|---|---|
| `internal/api` | HTTP + WebSocket handlers. `router.go` = the `Server` and its routes; `access.go` = `requirePermission`, `accessFor` / `engineForRequest` (every permission check, API key included: `webAccess`, or `keyAccess` = web access through the admin's API access policy, which `ceilingFor` uses too), `denyReason` and `isAdminRequest` (the one admin check); `errors.go` `writeError` / `writeErrorDetail` (every error answer, see `internal/problem`); `audited.go` `adminWrite` (an admin write: admin check + one audit entry for every answer; the handler adds the name with `noteFor(r)`); `middleware.go` (request log, body limit, SPA, JSON 404 / 405 for unknown `/api` `/ws` paths), `auth_handlers.go` (sign-in, LDAP, Azure AD, sessions, password), `resources.go` (namespaces, list / get, `serveYAML` = every YAML view but Secrets), `admin_users.go` (users, groups, roles, grants), `identity_config.go` (LDAP / Azure / session settings, LDAP import), `azure_directory.go` (Azure AD directory search through Microsoft Graph: test, search, import by object id; off by default), `audit_logs.go`, `logo.go`; more by feature (`apikeys.go` (API key sign-in, ceiling, expiry policy, `/api/me/api-keys`), `twofactor.go` (TOTP two-factor: the login code step `/api/auth/2fa/verify`, `/api/me/2fa/*`, admin reset; `authn()` = every route's sign-in check + the enrollment gate of a session the policy sends to set-up), `apikeys_admin.go` (admin key list / revoke, user API access preview), `workloads.go`, `deployment_actions.go`, `secrets.go`, `pod_exec.go` (shell socket), `pod_exec_command.go` (one command over REST), `logs.go` (pod / deployment / job log sockets, JSON frames, write deadline, at most 20 pods per workload; REST log `handlePodLogs`), `events_ws.go` (Live Events; `keepAlive` = the 25 s ping of every socket), `cluster_ctx.go` (the request's cluster: `X-OpenConsole-Cluster` from a tab, a key or a WebSocket ticket, else the stored pick), `kube_errors.go` (`writeReadError`: a failed cluster read → `cluster_forbidden` 403 / 404 / 502 / 503 / 504, logged), `openapi.yaml` + `openapi.go` (the hand-written API description, `GET /api/openapi.json`; `openapi_test.go` walks `routes()` against it), `clusters.go` (CRUD, default, `PUT /api/admin/clusters/order` = the admin's order every list uses), `ws_ticket.go`, `clientip.go` (client address: `X-Forwarded-For` only from `TRUSTED_PROXIES`), `origins.go` (CORS
`ALLOWED_ORIGINS`, WebSocket `CheckOrigin` = `wsOriginOK`, `WS_ORIGIN_CHECK`), `overview.go` (admin overview, 15 s cache), `search.go` (⌘K `GET /api/search`: informer cache only, `list` grants, no Secrets, not audited), `nodes.go` (admin node list / detail / history), `yaml_apply.go`, `views.go`, `exports.go`, …). `authz_test.go` = authorization suite |
| `internal/problem` | the error body of every answer: RFC 9457 problem details + `error` = reason code (`Codes`, each with its meaning; `errors_test.go` fails on free text, on a code missing from `openapi.yaml`'s `Problem` schema or from the UI's `ERROR_CODES`) |
| `internal/audit` | audit events: `Verb*` constants, `DetailKeys` registry (`event.go`), DB + console mirror (`logger.go`), 2.16 legacy upgrade (`legacy.go`). Handlers call `s.auditEvent` / `s.auditRead` / `s.auditReadDenied` (`api/audit_events.go`) |
| `internal/rbac` | permission engine (role → namespace / resource / action, cluster-scoped grants); `Catalog` (every resource:action), `NewAdmin`, `WithKey` (API key scope ∩ the owner's grants); `policy.go` API key policy: `SafeRead` (the one definition of safe read-only, UI template included), `KeyCeiling` (role modes / user override), `NewAdminKeys` |
| `internal/auth` | local passwords + policy, TOTP (`totp.go`, RFC 6238, stdlib) + the sign-in's in-memory code-step challenge (`challenge.go`), JWT sessions (inactivity timeout: `session_tokens.expires_at` moves on activity, polls and socket connects don't count; JWT `exp` = 12 h limit), LDAP, Azure AD (sign-in finds the account by Entra object id first), `graph.go` (Microsoft Graph with client credentials: `$search` users, `GraphRoot` per cloud from `AZURE_AD_AUTHORITY`) |
| `internal/kube` | per-cluster client + informer cache (`Manager`, `Registry`; nodes only with list + watch, pods indexed by `spec.nodeName`; a kind's lister only while `Usable(kind)` = synced and its watch not failing, else the live API; `Manager.Connected` = `openconsole_cluster_connected`; `Manager.StreamClient` = the client for followed logs, without the 30 s request timeout of ordinary calls), event bus, resource reads, apply, YAML prettify; `metrics.go` 30 s metrics-server sampler (24 h in memory, per pod / workload / node / cluster), `terminations.go` container exits from the pod informer (restart history), `search.go` name / IP search over the listers (`NewManagerWithCache` for tests) |
| `internal/prom` | Prometheus-compatible query client (API server proxy or URL; basic / bearer / Azure AD / mTLS), history queries, test-button diagnosis |
| `internal/store`, `internal/db` | SQLite store (users, roles, clusters + their Prometheus settings, sessions, views, recordings settings, restart history) and migrations; credentials encrypted at rest (`store/keys.go`: the key in the DB, or `ENCRYPTION_KEY_FILE` with re-encryption / rotation on start). `db.go`: WAL + `busy_timeout` + foreign keys, `Conn` (the one writer) + `Read` (audit reads, `VACUUM INTO`), `migrate` in one transaction, one-time `steps` counted in `PRAGMA user_version`; multi-statement writes go through `store.inTx` |
| `internal/backup` | database copies (`VACUUM INTO` → `BACKUP_DIR`): scheduled, before an upgrade (`db.OpenWithBackup`), Admin → Backups (`api/backups.go`, download only when allowed in the DB) |
| `internal/config` | env vars (`Load`; `Vars` = every one with default + description, `vars_test.go` scans the backend for reads), feature flags (`FEATURE_*`) |
| `internal/logging` | slog setup; `LOG_FORMAT=text|json|ecs` (`ecs.go`) |
| `internal/recording` | pod shell session recording (asciicast), quota / eviction |
| `internal/telemetry`, `internal/version` | OpenTelemetry tracing; build version |
| `internal/testutil/ldapfake` | in-process LDAP server for tests (`StartTLS` variant with a self-signed CA) |

`frontend/` (React 18, TypeScript, Vite, Tailwind, react-i18next, Monaco, xterm.js).
| Path | What |
|---|---|
| `src/pages/DashboardPage.tsx` | workloads screen (cards + table, tabs per kind; only the view in use renders, a stale or failed load never replaces the current list); `pages/dashboard/useNamespaceResources.ts` the tab's list (load order, 10 s poll, failing pods per workload), `DashboardModals.tsx` events / ConfigMap data, scale, restart, shell, YAML target, `NamespacePanel`, `ResourceTabs`; `ResourceListView.tsx` table columns, `ResourceCardsView.tsx` cards (same `ResourceViewProps`; a Logs handler is undefined without `pods:logs`); `PodDrawer` / `WorkloadDrawer` (Deployment, StatefulSet, DaemonSet; + `DetailParts`, `RestartHistory`) detail views; their Events and the row Events dialog follow the object live (`useObjectEvents`: REST for the last hour, then the namespace's `/ws/events`) |
| `src/pages/OverviewPage.tsx` | admin overview (`/overview`, admins land here); charts in `pages/overview/Charts.tsx`, line chart = `components/Usage` `LineChart`. A page without a Layout `panel` gets the full width |
| `src/pages/NodesPage.tsx` | admin node list (`/nodes`, `?node=<name>` opens the drawer); `pages/nodes/NodeDrawer.tsx` detail, `NodeParts.tsx` status badges, meter, search |
| `src/pages/AdminPage.tsx` | admin shell only (tab list, header, page error, state that outlives a tab switch: list + audit filters, users just added); each tab's section loads what it shows when it opens. `pages/admin/*`: `UsersTab` / `GroupsTab` / `RolesTab` (list + create / edit / delete dialogs; tables in `UsersSection` / `GroupsSection` / `RolesSection`) on `useDirectory` (users / groups / roles a tab needs, memberships from the lists), `RolePermissionsPanel` (+ `AddPermissionsModal`, `ClassicRolePermissions`), `IdentitySection` (`LdapSection`, `AzureAdSection`), `SessionSettingsSection` (timeout + API key expiry), `TwoFactorSection` (2FA policy, its own tab; stored with the session settings), `ClustersSection`, `CustomizationSection` (logo), `AuditSection` (its own debounced load; filters kept by AdminPage), sessions, recordings, `BackupsSection`, `PrometheusSettings`, `ApiKeysSection` (every user's keys), `ApiAccessParts` (role / user API access, preview), `SectionCard` |
| `src/pages/TwoFactorPage.tsx` | the user's two-factor authentication (`/account/two-factor`, account menu while the policy isn't off); `pages/account/`: `TwoFactorParts` (set-up flow, recovery codes), `TwoFactorEnroll` (App's blocking dialog when `/api/auth/me` says `twoFactor.enroll`), `CodeInput` (also LoginPage's code step) |
| `src/pages/ApiKeysPage.tsx` | the user's API keys (`/account/api-keys`, from the header account menu; `?tab=docs` = Documentation); `pages/apikeys/ApiKeyFormPage.tsx` create / edit, `ApiKeyParts.tsx` templates, expiry, secret box, `CopyRow`, `curlLine`; `ApiDocs.tsx` the Documentation tab, drawn from `/api/openapi.json` (greys out what the key ceiling doesn't reach) |
| `src/components` | `ui.tsx` (Button, Badge, `Segmented`, …), `PermissionMatrix` (resource × action toggles + catalog, Role Permissions and API keys), `MenuPopover` (keyboard menu: DataTable columns, account menu, row ⋯), `DataTable` (sort + `sortStorageKey`, column picker `columnsStorageKey` + `defaultHidden` columns, `keyboardNav`), `Drawer`, `ConfirmDialog`, `Combobox`, modals, `CommandPalette` (+ resource search, filter chips from `utils/paletteQuery.ts`, recently opened in localStorage), `LiveEventsPanel`, `LogViewer` (+ `utils/logStream.ts`: reconnect / resume), `ContainerPicker` (shell: which container), `DirectoryImportPanel` (LDAP / Azure AD import: search, basket kept across searches, per-person result), `DateField` (every date field: react-day-picker calendar, days outside min / max struck through; native date input on touch), `PodStatusBadge` (+ `PodRestarts`, `ContainerSquares`), `Usage` (meter + SVG line charts) |
| `src/hooks` | global / scoped keyboard shortcuts, modal scopes (`isTypingTarget`: inputs, Monaco, xterm), `useDialogFocus` (every modal dialog: focus in, Tab trapped, back to the opener) |
| `src/services/api.ts` | every API call; `wsUrl()` = WebSocket URL with a single-use ticket (never the JWT); every request names the tab's cluster (`tabClusterId`, learned from the first response); `utils/session.ts` inactivity timeout in the browser |
| `src/i18n.ts` | EN + TR dictionaries (one file; TR says "siz" and "parola"); sets `<html lang>`. `services/api.ts` `errorText`: reason codes → `apiErrors.*` |
| `src/shortcuts.json` | rows of the `?` cheat sheet with EN + TR text (`ShortcutsHelp`); docgen makes the docs page from it |
| `src/utils` | `formatDateTime` / `formatClock` (every date and time shown: ISO `2026-11-16 23:37:51`, local, 24 h, never `toLocaleString`), `formatAge`, `formatBytes`, `formatDuration`, Kubernetes quantities (`parseCpu` / `parseMem` / `formatCpu` / `formatMem`); `podStatus.ts` = kubectl STATUS logic, last container termination, exit code hints, `podOwner` ("Deployment/web"), `podController` (direct controller), `containerStates` (per-container look for the Containers squares); use it, don't re-derive pod health or ownership; `resources.ts` requests / limits sums; `kubeTypes.ts` the Kubernetes objects as structural types (`PodObject`, `WorkloadObject`, …; the API's JSON is assignable to them, no `any`); `searchText.ts` what the Dashboard search matches per tab (add a column → add its text there; the pod IP only while it shows); `openDashboard.ts` opens a Dashboard view or a pod / workload drawer from another page or the palette (an open Dashboard applies it via `DASHBOARD_STAGE_EVENT`) |

`deploy/`: kustomize manifests; `rbac.yaml` / `rbac-readonly.yaml` = ClusterRole of the token users paste in;
`elk/` = Elasticsearch ingest pipeline + mappings for the logs; `optional/` = not in the kustomization (NetworkPolicy). The Deployment uses `strategy: Recreate` (RWO + SQLite: never two pods). `.github/workflows/ci.yml` = tests + image publish (on a dev branch the publish job starts right after the tests; the docker build check + Trivy run on `main` and PRs).

Large files (`i18n.ts` ~2800 lines, `AdminPage.tsx`, `RolePermissionsPanel.tsx`): grep for the
part you need and read that range. New screens and handlers go in their own files, not into these.

## Commands

Toolchain (go, node, npm, docker, kubectl, k3d) is in `/opt/homebrew/bin`, which may not be on PATH:
`export PATH=/opt/homebrew/bin:$PATH`. Shell is zsh: write `${IMG}:latest`, never `$IMG:latest` (`:l` is a modifier).

```bash
# same as CI; run before every commit
cd backend  && go vet ./... && go build ./... && go test -race ./... && go run honnef.co/go/tools/cmd/staticcheck@v0.8.2 ./...
cd frontend && npm ci && npx tsc --noEmit -p . && npm run lint && npm test && npm run build

# local dev: backend on :8080 (DB in backend/data/), Vite on :5173 proxies /api and /ws
cd backend  && go run ./cmd/server
cd frontend && npm run dev
```
First login `admin` / `admin`, and every API call is 403 until the password is changed. No cluster is picked up
automatically. Scripted: `POST /api/auth/login` → `POST /api/auth/change-password` → login again →
`POST /api/admin/clusters` `{"name","method":"kubeconfig","kubeconfigBase64"}` → `POST /api/admin/clusters/{id}/activate`.

Smoke test before a PR: `docker build -t kubernetes-openconsole:local .`, run it, check `/healthz` + `/readyz`.
End to end: throwaway `k3d cluster create oc-smoke --kubeconfig-switch-context=false`, always use
`kubectl --context k3d-oc-smoke`, never touch other contexts, delete the cluster afterwards.
Fixtures: `kubectl --context k3d-oc-smoke apply -f hack/k3d/crashlab.yaml` (pods failing every common way, workloads of
each kind) and `hack/k3d/prometheus.yaml` (a Prometheus for the "in the cluster" mode); k3s ships metrics-server.
Don't pipe `go test` into grep in a chain that pushes: the pipe hides the failure.
Image: distroless (`static:nonroot`, runs as 100:101 like the old Alpine image, no shell, read-only root fs + `/tmp` emptyDir); Go version = `backend/go.mod`
`toolchain` line = Dockerfile `golang` tag = CI (`go-version-file`); base images pinned by digest, CI actions by commit SHA
(release in a comment); bump tag + digest / SHA together. Monaco is bundled (`components/monacoSetup.ts`), CSP is `'self'`.
**CI scans only warn** (govulncheck, `npm audit --omit=dev`, Trivy on the image): when a run shows a scan warning
(`gh run view <id>` annotations), tell the user what it found and ask whether to fix it; don't fix it unasked.
Screenshots: Playwright's `chromium.launch` dies on this Mac; start Chrome yourself with `--headless
--remote-debugging-port=9333` and use `chromium.connectOverCDP`. The dashboard reads `authToken`,
`dashboardNamespace`, `dashboardResourceTab`, `dashboardViewMode` (`card`|`list`), `uiLocale` from localStorage.

## When you add …

- **an endpoint** → route in `router.go`, the operation in `internal/api/openapi.yaml` (tag, summary, `x-openconsole-permission` / `-admin` / `-api-key`; `TestOpenAPIMatchesRouter` fails without it), `requirePermission`, audit for success + denied + failed
  (reads: `auditRead` / `auditReadDenied`; an admin write: wrap it in `adminWrite(verb, kind, h)` in the admin-writes group), a case in `authz_test.go`, `services/api.ts`.
  Errors only through `writeError(w, status, problem.X)` / `writeErrorDetail(…, detail)`: a reason code, never free
  text (English detail goes in `detail`). A new code → `problem.Codes` + the `Problem` enum in `openapi.yaml` +
  `ERROR_CODES` and `apiErrors.*` (EN + TR). The API has no version prefix: never break it (rename / remove a
  field or path, change a code's meaning); add instead. `info.version` in the served OpenAPI is the build's. Check permissions
  only through `requirePermission` / `s.can` / `engineForRequest` and admin through `isAdminRequest` (they
  know the API key; never `user.IsAdmin` for access), and add an API key case (allowed / refused) in
  `apikeys_test.go`; `/api/admin/*` routes are scanned there automatically. Something a key must never do:
  `denyAPIKey`.
- **an audit detail key** → `audit.DetailKeys` + `audit.DetailDocs` + `deploy/elk/openconsole@mappings.component-template.json`.
  A new verb → `audit.Verbs` + `VerbDocs`. Keep `Verb` / `ResourceType` / `Outcome` constants (or helper parameters
  called with constants): docgen reads the actions from the code and fails on what it can't follow.
  Never write secret values, YAML bodies, passwords or tokens into audit or logs.
- **UI text** → key in both EN and TR in `i18n.ts` (the parity test fails otherwise; `i18nLiterals.test.ts` fails on English left in JSX).
- **an env var / feature flag** → `config.Vars` (or `api.AllFeatures` + `api.FeatureDocs`) + `deploy/deployment.yaml` comment.
- **a metric** → `api.Metrics` (help text lives there only). **A permission** → `rbac.Catalog` + `rbac.ActionDocs` if
  the generic text doesn't fit. **A keyboard shortcut** → `frontend/src/shortcuts.json` (EN + TR text) + the binding.
- **a Kubernetes API the app reads or writes** → `deploy/rbac.yaml` and `deploy/rbac-readonly.yaml`, each rule with a
  comment above it saying what it is for (docgen fails without).
- **any of the above** → `cd backend && go run ./cmd/docgen` and commit `docs/reference/` (CI fails on a diff). New
  fixed text in docgen (a title, an intro, a table header) needs its Turkish in `cmd/docgen/tr.go` (docgen stops without).
- **a UI poll** → send `X-OpenConsole-Refresh: auto` (`autoRefresh(true)` in `api.ts`) so it isn't audited and doesn't count as activity (otherwise an open tab never times out).
- **a handler that reads the cluster** → on error `writeReadError(w, r, err, resource)`, never a bare 404 / 503.
- **a DB column / table** → migration in `internal/db` (idempotent `CREATE` / `ALTER`, or a new entry at the end of
  `steps` for a one-time change such as a table rebuild; never edit a shipped step; store tests upgrade an old schema).
  A new encrypted column → `store.encryptedColumns`.
- **any UI** → light + dark theme, TR + EN, keyboard reachable, axe clean (frontend tests run axe); a dialog uses `Modal` / `Drawer` or
  `useDialogFocus`; fields (`Input`, `NativeSelect`, `Combobox`, `DateField`) are `h-9` like `Button` md, so a bordered button in a row of
  fields is md, and a filter bar is an equal-column grid (Admin → Audit); a `w-*` / `h-*` className replaces the field's default; a screen is lazy-loaded in `App.tsx`; hooks pass `npm run lint` (`eslint.config.js`: rules-of-hooks + exhaustive-deps;
  react-hooks 7's React Compiler rules stay off: the app doesn't use the compiler and their fixes change behaviour).
- **anything a user or operator notices** → the docs site (below); the README only if a highlight or the quick start
  changes.

**Every app change updates the docs too.** A change to the app is not finished until the docs site
([k8sopenconsole/k8sopenconsole.github.io](https://github.com/k8sopenconsole/k8sopenconsole.github.io)) says the
same: the affected pages in English **and Turkish** (`i18n/tr/…`, terms of the app's TR UI, `i18n/tr/GLOSSARY.md`),
its screenshots if a screen changed (`screenshots/`: record → shoot), and the generated reference (docgen here, then
`reference.json` + `npm run reference:sync` there). Open the docs PR with the code PR and merge it when the code
reaches `dev`: it lands in the site's unreleased "Next" docs, which a release freezes (see Release). The PR
description names the pages it touches.

## UI / UX

Designs follow the project design system, generated with
[ui-ux-pro-max-skill](https://github.com/nextlevelbuilder/ui-ux-pro-max-skill) ("real-time operations",
data-dense, status colors green / amber / red, dark + light). The design system and the per-milestone design
notes live in the milestones repo (below), `kubernetes-openconsole/DESIGN_SYSTEM.md`. For new screens use
the skill (`/plugin marketplace add nextlevelbuilder/ui-ux-pro-max-skill`, then
`/plugin install ui-ux-pro-max@ui-ux-pro-max-skill`) and keep to the existing Tailwind tokens and
`components/ui.tsx`; don't introduce a second component library.

## Working style (ponytail)

Agent work on this repo runs with the [ponytail](https://github.com/DietrichGebert/ponytail) plugin
(`/plugin marketplace add DietrichGebert/ponytail`, then `/plugin install ponytail@ponytail`): the smallest
complete change, reuse what the repo already has, no unrequested options or abstractions, a test for risky logic.
- A deliberate shortcut gets a comment `shortcut: <the limit>, <when to upgrade>`; `/ponytail-debt` lists them.
- Review a change before the PR with `/ponytail-review`; whole-repo audit with `/ponytail-audit`.
- Without the plugin, follow the same rules by hand.

## Generated reference

`docs/reference/*.md` (env vars, permissions, audit events, metrics, Kubernetes permissions, keyboard shortcuts) is
written by `backend/cmd/docgen` from the registries above; never edit it by hand. The docs site copies it, plus
`internal/api/openapi.yaml` for the endpoint reference, from a pinned ref of this repo
(`reference.json` in the docs repo, `npm run reference:sync`); bump that ref when a release ships. Turkish pages
(`docs/reference/tr/`, same anchors as English) translate the fixed text from `cmd/docgen/tr.go`; descriptions from
the code stay English.

## Release

**Which number** (semver, `GOVERNANCE.md`), decided when the branch is opened and written in the milestone:
- **minor** (`2.27.0`): the release brings anything new: a screen or behaviour users notice, an endpoint, env var,
  permission, audit action, metric or DB migration step. Fixes that ship with it ride along. Docs: `docs:freeze`.
- **patch** (`2.26.1`, branch `2.26.1-name`): only fixes of what already exists, none of the above. Docs: the frozen `X.Y` pages.
- **major**: an API break; avoid it (the API is never broken, see "When you add …").

Feature branch `X.Y.Z-name` **from `dev`**: every push publishes `:dev-<run>` + `:dev-latest` → squash merge
into `dev` → the user tests `dev`'s pinned `:dev-<run>` on a real cluster → when the release's milestones are all
in `dev`, squash merge `dev` to `main` → `git tag -a vX.Y.Z`, push the commit and the tag together (`--atomic`) → CI builds once
and publishes `ghcr.io/vurulkan/kubernetes-openconsole:X.Y.Z` and `:latest` (same digest, amd64 + arm64,
GitHub attestations) → check digests, `gh attestation verify`, smoke test → `gh release create` →
**freeze the docs version** (minor releases: in the docs repo `npm run docs:freeze -- X.Y` with `reference.json`
pinned to the new tag; patch releases update the frozen `X.Y` pages instead; see its CLAUDE.md) + the release's docs
PR, then `gh workflow run docs.yml -R k8sopenconsole/k8sopenconsole.github.io` (the site's release notes).
A release runs CI once: push the release commit to `main` together with its tag (`git push --atomic origin <branch>:main vX.Y.Z`); that `main` run builds, tests and publishes `:X.Y.Z` + `:latest` (version from the `v*` tag on the commit). Tag pushes start no run; a `main` push without a tag publishes nothing (re-run it after pushing the tag). **Never `docker push` by hand**, never add `:<sha>` or
signature tags. The version comes from the tag (`dev-<run>` on branches; Dockerfile `ARG VERSION` →
`internal/version`, `dev` locally).

## Project files

Apache-2.0 (`LICENSE`; docs site CC BY 4.0). The product is **OpenConsole for Kubernetes** (short: OpenConsole), never "Kubernetes OpenConsole" (Linux Foundation marks: "Kubernetes" isn't the first word of a product name; the old name stays only in technical identifiers: repo, image, namespace, docs org). `CONTRIBUTING.md`, `GOVERNANCE.md`, `MAINTAINERS.md`, `SECURITY.md`
(private GitHub reports), `CODE_OF_CONDUCT.md` (CNCF), `ROADMAP.md`, `ADOPTERS.md`, `TRADEMARKS.md`, `.github/`
issue + PR templates: aimed at a CNCF Sandbox application. Commits are signed off (`git commit -s`, DCO). Keep
`ROADMAP.md` at the level of themes: open security findings stay in the private milestones repo.

## Planning

Milestones, decisions and status: <https://github.com/vurulkan/milestones> → `kubernetes-openconsole/`
(`README.md` index + standard steps, `STATUS.md`, `M*.md`). Check the current milestone before larger work.

Keep this file current: if you change the layout, a command or a rule above, update it in the same change.
