# Kubernetes OpenConsole

Modern, production-ready Kubernetes visibility and operations console with strict application-level authorization. Runs inside Kubernetes, reads cluster data using a single ServiceAccount identity per cluster, and enforces every access decision in the app layer (not via Kubernetes RBAC).

## Highlights

### Observability & live data
- **Informer-driven lister cache** — list endpoints read from a `client-go` SharedInformerFactory, so the UI is instant and the API server isn't hammered by polling.
- **Live Events side panel** — streams `added` / `updated` / `deleted` plus native `corev1.Event` objects over a WebSocket. Filter by All / K8s events / Warnings.
- **Prometheus `/metrics`**, dedicated `/livez` (process) and `/readyz` (DB) endpoints. Clusters are left out of readiness, so one unreachable cluster can't take the console down. See [Metrics](#metrics).
- **OpenTelemetry tracing** (opt-in): one span per API request, named after its route, with the Kubernetes API calls it made as child spans. Exported over OTLP/HTTP to any collector (Jaeger, Tempo, Elastic APM, …). See [Tracing](#tracing-opentelemetry).

### Workloads shown in the Dashboard
Pods, Deployments, **DaemonSets**, **StatefulSets**, **HorizontalPodAutoscalers (v2)**, Services, ConfigMaps, **Secrets**, Ingresses, CronJobs, Jobs — card view, list view, label filters, saved views.

### Write operations (opt-in per role, per namespace)
- **Deployment restart** (`deployments:restart`)
- **Deployment / StatefulSet scale** (`deployments:scale`, `statefulsets:scale`)
- **YAML view + edit + server dry-run + apply** for every workload above (`{resource}:edit`), powered by Monaco. Diff view, dry-run returns the server-canonicalized object, optimistic concurrency via `resourceVersion`.
- **Pod shell** (`pods:exec`) over WebSocket with xterm.js.
- **Pod shell session recording** — every shell is saved as an asciicast v2 file and can be replayed by admins (Admin → Recordings) with an in-browser player. See [Session Recording](#session-recording).
- **Secrets** (`secrets:list`, `secrets:get`, `secrets:reveal`, `secrets:edit`) — names, types and key names by default; values are revealed one key at a time, and secrets can be edited in the YAML editor (diff + dry-run). Every reveal and every YAML open is audited. See [Secrets](#secrets).
- **Pod / Deployment logs** (`pods:logs`) with rate limiting.

Every read and write is an audit event with its own fields: `action` (`deployment.restart`), `verb`, `outcome` (`success` / `denied` / `failed` / `rate_limited` / `locked`), the target cluster, namespace and resource, details such as `restarted_at` or `replicas_from` / `replicas_to`, and who / from where. See [Audit events](#audit-events). The HTTP response carries `X-Request-Id` for correlation with the audit line in stdout.

### Access & identity
- **User → Groups → Roles → per-cluster, per-namespace permissions** (application-level RBAC, no Kubernetes RBAC for end users).
- **Namespace discovery is permission-based** (no leakage of names you can't access).
- **Multi-cluster, per user**: save N clusters. Every user picks their **own** cluster in the header (or with `c`), and admins set a default for everyone else. Permissions can be scoped per cluster, and audit records the cluster.
- **Local users** (bcrypt) + **LDAP** (bind-based, searchable + importable) + **Azure AD** single-tenant login — all configurable via UI.
- **JWT authentication** with forced password change on first login.
- **Session management** (Admin → Sessions): list every active token, revoke individual sessions or every session for a user, change-password revokes everything.
- **Session recordings** (Admin → Recordings): filter, replay (1x / 2x / 4x, seek, skip idle), download `.cast`, delete; retention, quota and on/off switch editable in the UI.
- **Login brute-force protection** (5 fails per IP+user → 5-minute lock, audited). Every sign-in is audited as `user.login` with the outcome (`success` / `failed` / `locked`), the method (`login_method`: `local` / `ldap` / `azure`) and, for a failure, the reason.

### UX
- **Light / Dark / System theme** (persisted; respects OS).
- **Internationalization — English & Turkish** (locale switcher next to the theme toggle; defaults to browser language, persists user override). TR covers nav, Dashboard, Admin, audit, keyboard cheat sheet.
- **Keyboard-first navigation**: `⌘K` / `Ctrl+K` command palette, `?` cheat sheet, chord shortcuts for nav/theme, `c` cluster switcher, `v` saved views, `e` live events panel, `n` namespace filter focus. TR keyboard positions (`ğ` / `ü` / `.`) are mapped to the US `[` / `]` / `/` by physical key, so the shortcuts don't break on a TR Q layout.
- **Saved views** — store (cluster, namespace, tab, search, view mode) under a name on the server, so they follow you to any browser; **share** a view with every user.
- **Keyboard table navigation** — `j` / `k` move through rows of the admin tables, `Enter` opens, `d` deletes (with confirmation), `n` / `p` change page.
- **Label filters in the search box** — `label:app=foo`, `label:tier`, name tokens, AND-combined.
- **Audit logs** with pagination, filters, CSV export; **users and groups CSV export** for access reviews.
- **Accessible**: WCAG 2.1 AA contrast in light and dark themes, labelled controls, focusable scroll regions — checked with axe in the test suite and in a real browser.
- **Admin Role Permissions redesign** — role sidebar, grouped grant cards (namespaces that share identical grants merge), bulk Add Permissions modal with templates (Viewer / Developer / SRE / Admin), copy-from-role, inline edit.

### Security headers
- Strict CSP, `X-Frame-Options: DENY`, `Permissions-Policy`, `X-Content-Type-Options: nosniff`, `Referrer-Policy: strict-origin-when-cross-origin`.
- CSP allows `cdn.jsdelivr.net` and `worker-src blob:` so Monaco (lazy-loaded) can run; tighten these if you self-host Monaco in an air-gapped deploy.
- CSP `script-src` includes `'wasm-unsafe-eval'` so the bundled recording player can compile its WebAssembly terminal. It permits WebAssembly compilation only, not JavaScript `eval`.

## Architecture

- **Backend**: Go + `client-go` + chi router + slog + sqlite (modernc.org/sqlite).
- **Frontend**: React 18 + TypeScript + Vite + Tailwind + Monaco (lazy, CDN) + react-i18next + xterm.js + asciinema-player (lazy, bundled — no CDN).
- **Deployment**: single-container Docker image; Kubernetes manifests in `deploy/`.

## Build

### Option A — your own image

```bash
docker build -t kubernetes-openconsole:local .
```

### Option B — prebuilt image (GHCR)

```yaml
image: ghcr.io/vurulkan/kubernetes-openconsole:2.16.2   # pin a release
```

Images are multi-arch (**linux/amd64** and **linux/arm64**: Graviton, Ampere, Apple silicon); the runtime picks the right one. CI is the only publisher, and there are just two kinds of tags:

| Tag | Points to | Moves? |
|---|---|---|
| `X.Y.Z` (e.g. `2.16.2`) | that release | no — use this in production |
| `latest` | the newest release, same image (same digest) as its `X.Y.Z` | yes, on each release |

Releasing = push the `vX.Y.Z` git tag; CI builds once and pushes `:X.Y.Z` and `:latest`. Pushes to `main` are built and tested but not published.

#### Verifying an image

Every release image has a signed SLSA **build provenance** and an SPDX **SBOM** attestation, created by the CI workflow with [GitHub artifact attestations](https://docs.github.com/en/actions/security-for-github-actions/using-artifact-attestations) (Sigstore, keyless). They are stored on GitHub, so the registry holds nothing but the image tags.

```bash
# Provenance: built by this repository's CI from a release tag
gh attestation verify oci://ghcr.io/vurulkan/kubernetes-openconsole:2.16.2 \
  --repo vurulkan/kubernetes-openconsole \
  --signer-workflow vurulkan/kubernetes-openconsole/.github/workflows/ci.yml

# SBOM (packages in the image)
gh attestation verify oci://ghcr.io/vurulkan/kubernetes-openconsole:2.16.2 \
  --repo vurulkan/kubernetes-openconsole \
  --predicate-type https://spdx.dev/Document/v2.3 --format json \
  --jq '.[0].verificationResult.statement.predicate.packages | length'
```

Kyverno and the Sigstore policy-controller can check the same attestations before a pod is admitted. (2.14.0 and 2.14.1 were signed with cosign instead: `cosign verify` with `--certificate-oidc-issuer https://token.actions.githubusercontent.com`.)

### Tests

CI runs these on every push. Run them locally before you open a PR:

```bash
cd backend && go vet ./... && go test -race ./...    # recorder, exec bridge, RBAC engine, API, store, LDAP, Azure AD, tracing
cd frontend && npx tsc --noEmit -p . && npm test && npm run build
```

- The API tests run the real router and SQLite store against client-go's fake clientset. They check that every admin endpoint, namespace / resource / cluster-scoped grant, write action (403 + `denied` audit) and secret reveal is enforced, plus feature flags, saved views, CSV exports, the password policy and the exec session limit.
- Store tests upgrade a pre-2.x database schema and check that every migration is idempotent and that credentials are encrypted at rest.
- LDAP is tested end to end against an in-process LDAP server (configure → test → search → import → sign in → disable); Azure AD against a fake Entra token endpoint (state, audience, issuer and expiry are all rejected when wrong).
- Frontend (`npm test`, Vitest + Testing Library + axe-core): EN / TR dictionaries have the same keys and every `t('…')` key used in the code exists, table keyboard navigation, dialogs, and accessibility checks on the main components.

## Run (local Docker, no cluster)

```bash
docker run --rm -p 8080:8080 \
  -e TIMEZONE=Europe/Istanbul \
  -v kubernetes-openconsole-data:/data \
  ghcr.io/vurulkan/kubernetes-openconsole:2.16.2
```

The image defaults to `DATA_PATH=/data/app.db` and `STATIC_DIR=/app/public`; the SQLite DB and session recordings live under `/data`. Drop the `-v` for a throwaway instance. Then open http://localhost:8080 and add a cluster ([Connecting clusters](#connecting-clusters)).

## Kubernetes deploy

```bash
kubectl apply -k deploy/
```

This installs, in namespace `kubernetes-openconsole`:

| File | What |
|---|---|
| `namespace.yaml` | the namespace |
| `rbac.yaml` | ServiceAccount `openconsole-reader`, its long-lived token Secret, ClusterRole `openconsole-readonly` + binding. It produces the token you paste into the UI; see [Connecting clusters](#connecting-clusters). `rbac-readonly.yaml` is the [read-only](#read-only-mode) alternative. Not needed if you connect with your own kubeconfig identity |
| `pvc.yaml` | 5 Gi PVC for `/data` (SQLite + session recordings); a commented second PVC for recordings |
| `service.yaml` | ClusterIP Service on port 80 → container 8080 (put your Ingress / Gateway in front) |
| `elk/` | Optional, not applied by kustomize: Elasticsearch ingest pipeline, mappings and installer for the logs ([deploy/elk/README.md](deploy/elk/README.md)) |
| `deployment.yaml` | 1 replica (SQLite on a RWO volume — do not scale out), `:latest` image with `imagePullPolicy: Always`, every env var documented inline, requests / limits, `/livez` + `/readyz` probes, non-root, `seccompProfile: RuntimeDefault`, and **no ServiceAccount token mounted** (`automountServiceAccountToken: false`). The app never uses the pod's own identity |

Then:

1. Open the UI and log in as `admin` / `admin` ([First login](#first-login)).
2. Add the cluster in **Admin → Clusters** ([Connecting clusters](#connecting-clusters)). The backend never picks up a cluster on its own.

To upgrade, run `kubectl -n kubernetes-openconsole rollout restart deploy/kubernetes-openconsole`. The pod pulls `:latest`, i.e. the newest release. To stay on a fixed version, set a release tag (e.g. `2.16.2`) in `deployment.yaml` or through the `images:` override in `kustomization.yaml`, then re-apply.

## Environment variables

### Core
- `DATA_PATH` (default `/data/app.db` in the image) — SQLite DB location. Must be on a persistent volume.
- `STATIC_DIR` (default `/app/public` in the image) — Served React build output.
- `TIMEZONE` (default `UTC`) — Used for audit log timestamps.
- `LOG_RETENTION_DAYS` (default `30`) — Audit log retention (purged automatically).
- `MAX_REPLICAS` (default `100`) — Hard upper bound the Scale endpoint accepts for Deployment / StatefulSet scaling.

### Session recording
You normally set none of these. Recording is configured in **Admin → Recordings → Recording settings** and stored in the DB. The env vars below only **seed** those settings on the very first start, which is useful for scripted installs; after that, changing them has no effect. The exception is `SESSION_RECORDING_DIR`, which is read on every start and is the only one `deploy/deployment.yaml` mentions. See [Session Recording](#session-recording).

- `SESSION_RECORDING_ENABLED` (default `true`) — record new pod shell sessions.
- `SESSION_RECORDING_DIR` (default `<dir of DATA_PATH>/recordings`, i.e. `/data/recordings`) — where `.cast` files are written.
- `SESSION_RECORDING_RETENTION_DAYS` (default `30`, `0` = never purge) — daily purge of older recordings.
- `SESSION_RECORDING_MAX_SIZE_MB` (default `10`) — per-session cap; past it the recording stops and is flagged truncated.
- `SESSION_RECORDING_MAX_TOTAL_MB` (default `2048`) — quota for all recordings together.
- `SESSION_RECORDING_MIN_FREE_MB` (default `512`) — free space always left on the recordings volume.
- `SESSION_RECORDING_DISK_POLICY` (default `evict_oldest`) — `evict_oldest` or `stop`; see below.

### Security & limits
- `PASSWORD_MIN_LENGTH` (default `8`) — minimum length of local passwords (create, change, admin reset). Passwords are also capped at 72 bytes (bcrypt), must not be blank, and a change must actually change the password.
- `EXEC_IDLE_TIMEOUT` (default `5m`, minimum `30s`) — a pod shell with no input for this long is closed. Go duration syntax: `90s`, `10m`, `1h`.
- `MAX_EXEC_SESSIONS_PER_USER` (default `3`, `0` = unlimited) — concurrent pod shells per user; one more is refused with 429 and audited as `pod.exec` with outcome `rate_limited`.

### Feature flags
Switch a capability off **for everyone, admins included**, regardless of role permissions — for example to keep pod shells closed in production for a while. Set `FEATURE_<NAME>=false` (or `0` / `no`); anything else, or unset, leaves it on.

| Variable | Turns off |
|---|---|
| `FEATURE_POD_EXEC` | pod shell (`pods:exec`) |
| `FEATURE_YAML_EDIT` | YAML edit / apply on every resource except Secrets (`{resource}:edit`) |
| `FEATURE_WORKLOAD_ACTIONS` | deployment restart / scale, statefulset scale |
| `FEATURE_SECRETS` | the whole Secrets tab (every `secrets:*`) |
| `FEATURE_SECRET_REVEAL` | revealing secret values (`secrets:reveal`) |
| `FEATURE_SECRET_EDIT` | editing secrets (`secrets:edit`) |

A disabled feature disappears from the UI and every endpoint for it answers 403 *"this feature is disabled by the operator"* and writes the usual `denied` audit entry. `GET /api/features` shows the current state; the startup log lists what is off.

### Tracing (OpenTelemetry)
Off unless an OTLP endpoint is set. Uses the standard OpenTelemetry variables:

- `OTEL_EXPORTER_OTLP_ENDPOINT` (e.g. `http://otel-collector.observability:4318`) or `OTEL_EXPORTER_OTLP_TRACES_ENDPOINT` — OTLP/HTTP receiver. Setting either one turns tracing on.
- `OTEL_SERVICE_NAME` (default `openconsole`), `OTEL_RESOURCE_ATTRIBUTES`, `OTEL_EXPORTER_OTLP_HEADERS` (e.g. an API key), `OTEL_TRACES_SAMPLER` / `OTEL_TRACES_SAMPLER_ARG` (e.g. `parentbased_traceidratio` / `0.1`) — as defined by the OpenTelemetry spec.
- `APP_VERSION` and `APP_ENV` become `service.version` and `deployment.environment`.

Each API request is one span named after its route (`GET /api/namespaces/{namespace}/pods`) with `enduser.id`, `openconsole.cluster` and `openconsole.request_id`; the Kubernetes API calls it made are child spans. Incoming W3C `traceparent` headers are honoured, so a span from your ingress or gateway becomes the parent. Health probes and `/metrics` are not traced, and background informer traffic produces no traces. While tracing is on, every `http.request` log line also carries `trace_id`, so you can jump from a log line to its trace.

### Metrics
`GET /metrics` (Prometheus text format, unauthenticated — scrape it from inside the cluster; don't expose it through your Ingress):

| Metric | Meaning |
|---|---|
| `openconsole_http_requests_total`, `openconsole_http_requests_status_total{code}` | API requests, by status class |
| `openconsole_http_request_duration_ms_sum` / `_count` | request latency |
| `openconsole_cluster_requests_total{cluster}` | authenticated API requests per cluster |
| `openconsole_cluster_connected{cluster}` | 1 while OpenConsole holds a working connection to that cluster |
| `openconsole_pod_exec_sessions_total`, `openconsole_pod_exec_active` | pod shells started / open right now |
| `openconsole_pod_log_streams_total` | log streams opened |
| `openconsole_deployment_actions_total` | restart / scale actions |
| `openconsole_audit_events_total` | audit entries written |

### Structured logging (slog)
Logs go to stdout, one record per line. With `json` or `ecs` every line, including client-go's own messages, is a single JSON object, so Elastic Agent, Filebeat, Logstash, Fluent Bit or Vector can read it without grok. See [Shipping logs to Elastic](#shipping-logs-to-elastic).

- `LOG_FORMAT` (default `text`):
  - `ecs` — nested JSON following the [Elastic Common Schema](https://www.elastic.co/guide/en/ecs/current/index.html), the same shape as other ECS-logging services. Use this for Elastic. `deploy/deployment.yaml` sets it.
  - `json` — flat JSON with short field names (`time`, `level`, `msg`, `user`, …), for Loki / Vector or your own parsing.
  - `text` — for reading `kubectl logs` by eye.
- `LOG_LEVEL` (default `info`) — `debug` | `info` | `warn` | `error`. Successful health probes (`/healthz`, `/livez`, `/readyz`) and `/metrics` scrapes are logged at `debug` only, so they don't flood the log; failing ones still show up.
- `LOG_OUTPUT` (default `stdout`) — `stdout` | `stderr`.
- `LOG_ADD_SOURCE` (default `false`) — include the source file and line (`log.origin.*` in ECS).
- `LOG_INCLUDE_AUDIT` (default `true`) — mirror every audit entry to stdout, one line per action ([Audit events](#audit-events)). It carries the same request id as the matching HTTP request record. With `false` audited actions write nothing to stdout (the database still has them).
- `APP_ENV`, `APP_VERSION` — static labels on every record (`service.environment`, `service.version`). `deploy/deployment.yaml` sets `APP_ENV=prod`; change it per cluster. Release images already carry their version; set `APP_VERSION` only to override it, e.g. for a canary.

An HTTP request and an audit event with `LOG_FORMAT=ecs` (one line each; wrapped here):

```json
{"@timestamp":"2026-10-13T14:40:46.449346Z","log":{"level":"warn","logger":"http"},"message":"GET /api/namespaces 401",
 "service":{"name":"openconsole","version":"2.16.2","environment":"prod"},"ecs":{"version":"8.11.0"},
 "http":{"request":{"method":"GET","id":"bOPVk_3c0Qwaoe9g"},"response":{"status_code":401,"body":{"bytes":27}}},
 "url":{"path":"/api/namespaces"},"event":{"duration":509909,"kind":"event","category":["web"],"type":["access"],
 "outcome":"failure","dataset":"openconsole.app"},"source":{"ip":"10.31.67.52"},"user_agent":{"original":"Mozilla/5.0 …"}}

{"@timestamp":"2026-10-15T14:55:22.123456Z","log":{"level":"info","logger":"audit"},
 "message":"mustafav: deployment.scale success payments/nginx on prod-aks",
 "service":{"name":"openconsole","version":"2.17.0","environment":"prod"},"ecs":{"version":"8.11.0"},
 "event":{"action":"deployment.scale","kind":"event","category":["configuration"],"type":["change"],
 "outcome":"success","dataset":"openconsole.audit"},
 "openconsole":{"verb":"scale","outcome":"success","auth_source":"azure","cluster":"prod-aks","cluster_id":2,
 "namespace":"payments","resource_type":"deployment","resource_name":"nginx","replicas_from":3,"replicas_to":5},
 "user":{"name":"mustafav"},"http":{"request":{"id":"qXpB6yXONDiuXKX2"}},"source":{"ip":"10.31.67.52"},
 "user_agent":{"original":"Mozilla/5.0 …"}}
```

What each `json` field becomes in `ecs`:

| `json` | `ecs` |
|---|---|
| `time`, `level`, `msg` | `@timestamp` (UTC), `log.level` (lower case), `message` (for requests: `GET /path 401`; for audit events: `user: action outcome namespace/name on cluster (reason)`) |
| `service`, `version`, `env` | `service.name`, `service.version`, `service.environment` |
| `user`, `user_agent`, `remote_ip` | `user.name`, `user_agent.original`, `source.ip` |
| `method`, `path`, `status`, `request_id` | `http.request.method`, `url.path`, `http.response.status_code`, `http.request.id` |
| `duration_ms` | `event.duration` (nanoseconds, measured, not rounded) |
| — | `http.response.body.bytes` |
| `event` (audit action), `reason`, `error`, `trace_id` | `event.action`, `event.reason`, `error.message`, `trace.id` |
| everything else (`verb`, `outcome`, `cluster`, `namespace`, `resource_name`, audit details such as `replicas_to`, …) | `openconsole.<name>` |

Every `ecs` record also has `event.dataset`: `openconsole.audit` for audit events, `openconsole.app` for the rest. HTTP requests carry `event.kind: event`, `event.category: [web]`, `event.type: [access]` and `event.outcome` (`failure` for 4xx / 5xx). Audit events carry `event.kind: event`, `event.outcome` (`success`, or `failure` for denied / failed / rate_limited / locked; the exact value is in `openconsole.outcome`), `event.type` from the verb (`access` for reads, `change`, `creation`, `deletion`, `start` / `end` for shells and sign-ins) and, where it applies, `event.category` (`authentication`, `session`, `process`, `iam`, `configuration`). `log.logger` is `http` or `audit`.

`namespace` / `pod` / `container` describe the resource the action was performed on, so they live under `openconsole.*`. The shipper's own `kubernetes.*` and `container.*` fields describe the OpenConsole pod that wrote the line. The two never mix.

Every HTTP response also carries an `X-Request-Id` header matching the request id.

### Audit events

Every audited action is one event, stored in the database (Admin → Audit Logs, CSV) and, with `LOG_INCLUDE_AUDIT=true`, written to stdout as one `audit` line. The same fields are everywhere, so filters work the same in the UI and in Kibana:

| Field (`json` / DB) | `ecs` | Meaning |
|---|---|---|
| `event` / `action` | `event.action` | `<resource type>.<verb>`: `deployment.list`, `deployment.restart`, `pod.exec`, `secret.reveal`, `user.login`, `permission.create` |
| `verb` | `openconsole.verb` | `list` `get` `logs` `exec` `restart` `scale` `apply` `view_yaml` `reveal` `view` `download` `create` `update` `delete` `share` `select` `activate` `deactivate` `revoke` `export` `import` `login` `change_password` `reset_password` `evict` `purge` |
| `outcome` | `openconsole.outcome`, `event.outcome` | `success` `denied` `failed` `rate_limited` `locked` (`event.outcome` is `success` / `failure`) |
| `reason` | `event.reason` | why it was denied or failed: `forbidden`, `feature_disabled`, `admin_only`, `k8s_forbidden`, `not_found`, `conflict`, `bad_password`, … |
| `user`, `auth_source` | `user.name`, `openconsole.auth_source` | who, and where the account signs in (`local` / `ldap` / `azure`) |
| `remote_ip`, `user_agent`, `request_id` | `source.ip`, `user_agent.original`, `http.request.id` | from where; the request id matches the `http.request` line |
| `cluster`, `cluster_id` | `openconsole.cluster`, `openconsole.cluster_id` | the cluster the action **targeted**. Empty for actions that don't run on a cluster (sign-ins, users, groups, roles, settings, sessions, saved views). A permission grant records the grant's cluster (empty for "all clusters"), not the cluster the admin had selected. |
| `namespace`, `resource_type`, `resource_name` | `openconsole.*` | the target; `resource_type` is singular (`deployment`), `resource_name` is the bare name, `*` for a list |
| details | `openconsole.<key>` | typed, see below |

Details are a fixed set of keys, each with a type in the Elastic mapping:

| Action | Details |
|---|---|
| `deployment.restart` | `restarted_at` (date) |
| `deployment.scale`, `statefulset.scale` | `replicas_from`, `replicas_to` |
| `<kind>.apply` | `dry_run`, `yaml_from`, `yaml_to` (sha256 prefixes, never the YAML) |
| `pod.exec` | `phase` (`start` / `end`), `container`, `command`; at the end `exit_code`, `bytes_in`, `bytes_out`, `duration_ms` |
| `pod.logs`, `deployment.logs`, `job.logs` | `container` / `pods` |
| `secret.reveal` | `key` (the key name, never the value) |
| `recording.*` | `pod`, `container`, `owner`, `started_at`, `size_bytes`, `truncate_reason`, `count`, `retention_days` |
| `user.login` | `login_method`, `linked_by`, `signed_in_as`, `account_source` |
| `user.*`, `group.*`, `role.*`, `permission.*` | `changed` (field names, not values), `is_admin`, `is_active`, `account_source`, `groups`, `count`, `role`, `grant` (`deployments:restart`), `auto_provisioned` |
| any failure | `error` (→ `error.message` in ECS) |

Reads are audited too (`deployment.list`, `pod.get`, `pod.logs`, …), including a refused one (`denied`, reason `forbidden`). Lists the UI fetches on its own are not: the dashboard's reload every 10 seconds, and the namespace list behind the command palette and the role editor (they send `X-OpenConsole-Refresh: auto`). The lists you open are audited, and the HTTP request log still has every request.

Kibana examples:

```text
openconsole.verb : "exec" and openconsole.cluster : "Zenia-NonProd"
event.action : "deployment.restart" and event.outcome : "failure"
openconsole.resource_name : "boh" and openconsole.namespace : "boh-cy"
openconsole.replicas_to >= 10
event.action : "pod.exec" and openconsole.phase : "end" and not openconsole.exit_code : 0
openconsole.outcome : "denied" and user.name : "dev1"
```

#### Upgrading from 2.16

Before 2.17 the outcome was part of the action (`deployment.restart.success`), reads were a bare verb (`list` with `resource_type: deployments`) and details sat in the resource name (`boh (restartedAt=…)`).

- **Database**: on the first start of 2.17 the existing audit rows get the new `action`, `verb`, `outcome` and a singular `resource_type`. Their resource names keep the old `(k=v)` suffix; with the default 30-day retention those rows age out on their own.
- **API**: `?action=deployment.restart.success` still works; the outcome is split off.
- **Elastic**: re-run `deploy/elk/install.sh`. The new mapping applies from the next rollover of `logs-openconsole.audit-*` (`POST logs-openconsole.audit-default/_rollover` to apply it now). The pipeline gives 2.16 lines the 2.17 shape (action without the outcome, `openconsole.verb`, `openconsole.outcome`, `event.type`), so one query finds old and new events. Saved searches, visualizations and alerts that filter on `event.action : *.success` / `*.denied` must be changed to `event.action` + `event.outcome` (or `openconsole.outcome`).
- **Console**: the extra `deployment.action`, `workload.action`, `secret.action`, `yaml.apply`, `recording.action`, `pod.exec.start` / `pod.exec.end`, `*.logs.start`, `user.password_reset` and `user.auto_provision` lines are gone, and so are the `level=error` lines `deployment.restart.failed`, `deployment.scale.failed`, `statefulset.scale.failed` and `<resource>.apply.failed`; the `audit` line has all their fields. A failed action is `event.outcome : "failure"` with `event.reason` and `error.message`. `level=error` is left for faults in OpenConsole itself (e.g. `http.panic`).

#### Shipping logs to Elastic

Pick the variant that matches your setup. All of them read the container's stdout and need no grok.

**Elastic Agent managed by Fleet, with the Kubernetes integration already collecting container logs (recommended).** Leave the integration as it is and run [`deploy/elk/install.sh`](deploy/elk/README.md) once against Elasticsearch:

```bash
ES_URL=https://elasticsearch.example:9200 ES_API_KEY=<base64 id:key> deploy/elk/install.sh
```

It installs an ingest pipeline that the Kubernetes integration calls for every container log line (through `logs-kubernetes.container_logs@custom`). The pipeline:
- decodes only OpenConsole's lines, so other pods' lines stay as they are;
- keeps Agent's `kubernetes.*` / `container.*` / `log.file.path` fields;
- sets `event.outcome` on audit events, and gives audit lines from before 2.17 the 2.17 shape (see [Upgrading from 2.16](#upgrading-from-216));
- routes the records to two data streams with proper mappings: `logs-openconsole.audit-*` (audit events) and `logs-openconsole.app-*` (everything else).

This is a one-time step on the Elasticsearch side; nothing changes in the Agent policy. **Without it the logs still arrive, but unparsed.** Each line sits as one JSON string in `message` in `logs-kubernetes.container_logs-*`, so there is no `user.name` / `event.action` / status code to filter or chart on, audit and application records are mixed, and `@timestamp` is the time Agent read the line. If you can't run the script, the same four requests can be sent from Kibana Dev Tools ([deploy/elk/README.md](deploy/elk/README.md#without-installsh)).

Requires Elasticsearch 8.8 or later. Tested on 8.15.3 and 9.1.0 with real OpenConsole lines; see [deploy/elk/README.md](deploy/elk/README.md) for the details, KQL examples and how to remove it.

**Elastic Agent standalone, or Filebeat.** Add a filestream input for the OpenConsole pods' log files. The `container` parser strips the CRI prefix and `ndjson` decodes the record into the root:

```yaml
- type: filestream
  id: openconsole
  paths:
    - /var/log/containers/kubernetes-openconsole-*_kubernetes-openconsole_*.log
  parsers:
    - container: {}
    - ndjson:
        target: ""
        overwrite_keys: true   # @timestamp and message come from the record
        expand_keys: true      # only needed for lines from 2.16.1 (dotted keys)
        add_error_key: true
  processors:
    - add_kubernetes_metadata: {}
```

In Elastic Agent standalone this goes under `inputs:` with a `data_stream: {dataset: openconsole}`; in Filebeat under `filebeat.inputs:`. Exclude these files from your generic container input so lines aren't shipped twice.

**Logstash.** The `json` filter puts the keys at the root and takes `@timestamp` from the record:

```ruby
filter {
  if [kubernetes][labels][app] == "kubernetes-openconsole" {
    json { source => "message" skip_on_invalid_json => true }
  }
}
```

With `LOG_FORMAT=json` instead of `ecs`, decode into a sub-object so the short names can't collide with ECS fields: `ndjson` with `target: "openconsole"`, or `json { source => "message" target => "openconsole" }`, plus a date mapping for `openconsole.time`.

### Azure AD OAuth (only if used)
Configured through **Admin → Azure AD** at runtime. The only env var is for national clouds:

- `AZURE_AD_AUTHORITY` (default `https://login.microsoftonline.com`) — e.g. `https://login.microsoftonline.us` (US Government) or `https://login.chinacloudapi.cn` (China).

### LDAP (only if used)
Configured through **Admin → LDAP** at runtime — no env vars.

---

# Connecting clusters

OpenConsole talks to each cluster as one ServiceAccount and enforces per-user access itself (Users → Groups → Roles). The ServiceAccount's ClusterRole is the ceiling: no user can do more than it allows, whatever their role says.

Clusters are added **only in the UI** (Admin → Clusters). Two methods: **ServiceAccount Token** (API server URL + token + CA) or **Kubeconfig** (upload a file). Credentials are validated against the API server before they are saved (a real namespace list call, so a wrong server, token or CA is rejected) and stored encrypted in SQLite. Each user works on the cluster they pick in the header; see [Choosing your cluster](#choosing-your-cluster). The default cluster is connected at startup.

## 1. Create the ServiceAccount on the cluster

This step is for the **ServiceAccount Token** method, and for a kubeconfig built from that token (3b). If you connect with a kubeconfig whose identity you already manage, skip it. That identity's RBAC then has to cover what OpenConsole should do; the table below shows what each rule enables.

The OpenConsole pod does **not** run as this ServiceAccount. `deployment.yaml` sets no `serviceAccountName` and turns off token automount, because the app only ever uses the credentials stored in Admin → Clusters. The ServiceAccount exists to mint the token you paste into the UI.

Do this on every cluster you will connect with a token, including the one OpenConsole runs in. `deploy/rbac.yaml` creates:

- ServiceAccount `openconsole-reader` (namespace `kubernetes-openconsole`)
- Secret `openconsole-reader-token`: a long-lived token; Kubernetes fills in `token` and `ca.crt`
- ClusterRole `openconsole-readonly` and a binding to the ServiceAccount

For the cluster OpenConsole runs in, `kubectl apply -k deploy/` already did this. For a remote cluster:

```bash
kubectl --context <remote> create namespace kubernetes-openconsole
kubectl --context <remote> apply -f deploy/rbac.yaml
```

What the ClusterRole allows, and which application permission needs it. Delete the rules for permissions you will never grant:

| ClusterRole rule | Needed for |
|---|---|
| `namespaces, pods, services, configmaps, events`: get / list / watch | every Dashboard tab, Live Events |
| `secrets`: get / list | `secrets:list`, `secrets:get`, `secrets:reveal` |
| `secrets`: update | `secrets:edit` |
| `pods/log`: get | `pods:logs`, deployment / job logs |
| `pods/exec`: create | `pods:exec` (shell) |
| `pods, services, configmaps`: update | `{resource}:edit` (YAML apply) |
| `deployments, daemonsets, statefulsets`: get / list / watch / update | tabs + `edit` |
| `deployments`: patch | `deployments:restart` |
| `deployments/scale, statefulsets/scale`: get / update | `deployments:scale`, `statefulsets:scale` |
| `horizontalpodautoscalers, ingresses, cronjobs, jobs`: get / list / watch / update | tabs + `edit` |

### Read-only mode

To run OpenConsole purely as a viewer, use `deploy/rbac-readonly.yaml` instead of `deploy/rbac.yaml`. It defines the same ServiceAccount, token and binding names, with a ClusterRole that has only `get` / `list` / `watch`.

```bash
kubectl apply -f deploy/rbac-readonly.yaml          # instead of rbac.yaml
# with kustomize: replace rbac.yaml with rbac-readonly.yaml in deploy/kustomization.yaml
```

| | Works | Refused by Kubernetes (403) |
|---|---|---|
| `rbac-readonly.yaml` | every Dashboard tab, Live Events, pod / deployment / job logs | restart, scale, YAML apply, pod shell. Secrets are not included at all |

- The Kubernetes RBAC is the hard limit. Even if an OpenConsole role grants `edit` or `exec`, the API server refuses the call. Still, leave write actions out of your OpenConsole roles too, so users don't see buttons that only fail.
- Logs are included. Drop the `pods/log` rule if read-only should also mean "no logs".
- Secrets are excluded on purpose. At the Kubernetes level `get` on secrets means reading values, so enabling the commented rule makes OpenConsole's `secrets:reveal` permission the only protection. If you only need secret metadata, uncomment it and grant `secrets:list` / `secrets:get` only.
- With the **Kubeconfig** method the same rule applies: OpenConsole can do exactly what the kubeconfig's identity can. A kubeconfig built from this ServiceAccount's token (step 3b) gives you a read-only console. So does a kubeconfig for any identity of your own that only has get / list / watch, without applying either rbac file.
- To go back to full access, apply `deploy/rbac.yaml`. `kubectl apply` replaces the rule list in place; nothing needs to change in the UI.

## 2. Read the token and CA

Run this against the cluster you are adding:

```bash
NS=kubernetes-openconsole
TOKEN=$(kubectl -n $NS get secret openconsole-reader-token -o jsonpath='{.data.token}' | base64 -d)
CA=$(kubectl -n $NS get secret openconsole-reader-token -o jsonpath='{.data.ca\.crt}')   # already base64 — use as-is
SERVER=$(kubectl config view --minify -o jsonpath='{.clusters[0].cluster.server}')
```

`SERVER` must be reachable **from the OpenConsole pod**. For the cluster OpenConsole runs in, use `https://kubernetes.default.svc`.

## 3a. Add it with the ServiceAccount Token method

**Admin → Clusters → Add Cluster**:

| Field | Value |
|---|---|
| Name | anything, e.g. `prod-west` |
| Method | `ServiceAccount Token` |
| API Server | `$SERVER` (or `https://kubernetes.default.svc` for the local cluster) |
| Token | `$TOKEN` |
| CA Cert (base64) | `$CA`. Leave it empty only if the API server certificate is signed by a public CA. |

**Save Cluster** validates the connection. Then click **Set as default** on the cluster card. Users who haven't picked a cluster work on the default; everyone can switch to another cluster their permissions cover.

## 3b. Or with the Kubeconfig method

Upload a kubeconfig under **Method: Kubeconfig → Upload kubeconfig**. It can be any kubeconfig whose identity uses a static token or client certificate, with the RBAC you want (in that case step 1 is not needed). Or build one from the ServiceAccount token above:

```bash
cat > openconsole-prod-west.kubeconfig <<EOF
apiVersion: v1
kind: Config
clusters:
- name: target
  cluster:
    server: ${SERVER}
    certificate-authority-data: ${CA}
users:
- name: openconsole-reader
  user:
    token: ${TOKEN}
contexts:
- name: openconsole
  context:
    cluster: target
    user: openconsole-reader
current-context: openconsole
EOF
```

> Don't upload your personal kubeconfig. Kubeconfigs that authenticate through an exec plugin (`kubelogin`, `aws eks get-token`, `gke-gcloud-auth-plugin`) don't work: the container has none of those binaries. They would also make OpenConsole act as you instead of as the ServiceAccount.

## Token rotation

```bash
kubectl -n kubernetes-openconsole delete secret openconsole-reader-token
kubectl apply -f deploy/rbac.yaml   # Kubernetes issues a new token
```

Then edit the cluster in Admin → Clusters, tick **Replace credentials** and paste the new token (or upload the new kubeconfig). The old token stops working as soon as its Secret is deleted.

If you would rather use an expiring token: `kubectl -n kubernetes-openconsole create token openconsole-reader --duration=8760h`. You must replace it in the UI before it expires.

## Troubleshooting

- **Validation fails on Save**: the API server is not reachable from the pod (network policy, private endpoint), or the CA does not match.
- **Secrets tab: "ServiceAccount is not allowed to read secrets"**: the ClusterRole lacks the `secrets` rule. Re-apply `deploy/rbac.yaml`.
- **A tab is empty or 403 for a user**: check that user's role permissions first, then the ClusterRole rule in the table above.

---

# Application permissions

Granted per role, per namespace, per cluster (or all clusters) under **Admin → Roles**. Admins implicitly have everything.

| Resource | Actions |
|---|---|
| pods | `list`, `get`, `logs`, `exec`, `edit` |
| deployments | `list`, `get`, `restart`, `scale`, `edit` |
| daemonsets, hpas, services, configmaps, ingresses, cronjobs, jobs | `list`, `get`, `edit` |
| statefulsets | `list`, `get`, `scale`, `edit` |
| secrets | `list`, `get`, `reveal`, `edit` |

Templates in the Add Permissions modal: Viewer (read only, including secret *metadata*), Developer (+ restart / scale), SRE (+ edit on common workloads, pod exec), Admin (everything, including `secrets:reveal` and `secrets:edit`). Any of these can also be granted one by one to any role, so regular users can be given secret access per namespace without being admins.

---

# Pod Shell (exec)

Interactive shell into a running container, gated by application permission `pods:exec`. Off by default on every role; admins opt in per role, per namespace.

- Endpoint: `GET /ws/namespaces/{namespace}/pods/{name}/exec?container=<c>&command=/bin/sh` (WebSocket).
- xterm.js UI with container picker on multi-container pods and shell picker (`/bin/sh`, `/bin/bash`, `/bin/ash`).
- Idle timeout: **5 minutes** without input closes the session (`EXEC_IDLE_TIMEOUT`).
- At most **3** open shells per user (`MAX_EXEC_SESSIONS_PER_USER`); the next one is refused with 429 and audited as `pod.exec.rate_limited`.
- Each session writes two `pod.exec` audit events, `phase: start` (container, command) and `phase: end`. The end event carries `exit_code` (the shell's exit status; `-1` when the session was cut — idle timeout, closed tab, network), `bytes_in`, `bytes_out` and `duration_ms`. A shell that ends with a non-zero status, e.g. after a failed last command, is a normal end (outcome `success`).
- Can be switched off for everyone with `FEATURE_POD_EXEC=false` ([Feature flags](#feature-flags)).
- Terminal output is recorded by default — see [Session Recording](#session-recording).
- ClusterRole must grant `pods/exec: create` for this to work.

**Security notes**
- Exec is the highest-risk action in OpenConsole; grant it narrowly.
- Non-root pod admission policies in your cluster still apply.

# Secrets

The Secrets tab (after ConfigMaps) uses four permissions. Seeing that a secret exists, reading a value and changing it are separate grants. Admins have all four; give them to other users per namespace through their roles (Admin → Roles).

| Permission | Returns |
|---|---|
| `secrets:list` | name, type, key count, age |
| `secrets:get` | the **Keys** modal: type, immutable flag, labels, annotations, key names and sizes |
| `secrets:reveal` | **Show** on a key: that one key's value, plus copy / hide buttons |
| `secrets:edit` | the **YAML** button: the same editor as other resources (read-only view → Edit → Dry-run → diff → Apply) |

- Values never leave the server on `list` / `get`. The `kubectl.kubernetes.io/last-applied-configuration` annotation, which embeds the data, is dropped too.
- `reveal` is a POST for a single key, sent with `Cache-Control: no-store`. Binary values come back base64-encoded and labelled as such. Revealed values are discarded when the modal closes.
- Every reveal is audited as `secret.reveal` (success / denied / failed) with the namespace, secret and the key name in `key` (never the value).
- **Editing (`secrets:edit`)**: the YAML shows text values as plain-text `stringData`, so you edit readable values instead of base64. Binary values stay base64 in `data`. On apply Kubernetes merges `stringData` into `data`. Removing a key from the YAML deletes it. The dry-run result comes back in the same shape, so the before / after diff compares like with like.
- The YAML holds every value, so opening it requires `secrets:edit`; `get` or `reveal` is not enough. Each open is audited as `secret.view_yaml`, and changes as `secret.apply`, the same as other resources. Optimistic concurrency applies too: a stale `resourceVersion` gives a 409.
- Secrets are not held in the informer cache. Each request reads from the API server, so no secret values sit in OpenConsole's memory.
- Needs the `secrets` rule in the ClusterRole: get / list, plus `update` for `secrets:edit`.

# Session Recording

Every pod shell session is recorded as an [asciicast v2](https://docs.asciinema.org/manual/asciicast/v2/) file and can be replayed by admins. Recording lives entirely inside OpenConsole — no extra ClusterRole permissions.

**What is recorded**
- Everything the container writes to the terminal (stdout + stderr — merged, since the shell runs on a TTY), with timing, plus terminal resizes.
- Keystrokes are **not** recorded as input events. Anything the shell echoes back (typed commands, for example) is part of the output and therefore in the recording; input at hidden prompts (`sudo`, `read -s`) is not echoed and is not recorded.
- Escape sequences from full-screen programs (`vim`, `less`, `top`) are kept as-is, so they replay faithfully.
- Metadata per session: user, cluster, namespace, pod, container, start / end, size, truncated flag, and the `request_id` of the exec request.

**Privacy.** If someone prints a secret (`cat` of a mounted secret, `env`, `kubectl get secret -o yaml`), that secret is now in the recording. The shell shows a red *"This session is being recorded"* banner that says so. The banner only appears when the server confirms that the session is actually being recorded. Recordings are admin-only, and every view or download is audited. Treat the recordings volume like the audit database.

**Playback (Admin → Recordings)**
- Filter by user, namespace, pod and date range. The table shows duration, size, and *in progress* / *truncated* badges.
- ▶ opens an in-browser player: play / pause, timeline seek, 1x / 2x / 4x, and "skip idle time" (squeezes pauses longer than 2 s).
- ⬇ downloads the `.cast` file, after a confirmation that warns the file may contain secrets and must not be shared in tickets / chat / email. It plays in the `asciinema` CLI too: `asciinema play file.cast`.
- 🗑 deletes the file and its row. A recording whose session is still running can't be deleted.

**Settings (Admin → Recordings → Recording settings).** On/off, retention, per-session cap, total quota, free-space floor and disk policy. Changes apply to new sessions immediately, with no restart; a running session keeps the limits it started with. Lowering the retention triggers a purge right away.

**Disk protection.** By default recordings share the PVC with `app.db`. If that volume filled up, SQLite could no longer write, and login and audit would break with it. Two limits prevent this. Both are checked before every new session and every 30 s while sessions are running:

| Limit | Default | Meaning |
|---|---|---|
| Total quota | 2048 MB | All recordings together, plus room for one more full-size session |
| Free-space floor | 512 MB | Always left free on the recordings volume |

When a limit would be crossed, the **disk policy** decides what happens:

- `evict_oldest` (default) — the oldest finished recordings are deleted, even before their retention ends, until the next session fits. Each eviction is audited as `recording.evict` (user `system`, reason `quota` / `low_disk`).
- `stop` — existing recordings are kept. New shells still open but are **not** recorded (`recording.create` failed, reason `disk_quota`), and running recordings stop with a truncation marker. The admin screen shows a warning until space is freed.

The shell itself is never blocked by recording: a disabled, full or broken recorder only means the session isn't recorded. For full isolation, give recordings their own PVC; `deploy/pvc.yaml` and `deploy/deployment.yaml` contain a commented example. Then set `SESSION_RECORDING_DIR=/recordings`.

**Retention.** A background job runs one minute after start and then daily. It deletes recordings older than the retention period (row and file, audited as `recording.purge` with `count`) and removes stray `.cast` files that have no database row. If the process crashes mid-session, the next start closes the open row using the file's size and modification time.

**Audit events**

| Event | When |
|---|---|
| `recording.create` success | Session end — the session id as the resource, `pod`, `container`, `size_bytes`, `duration_ms`, `truncate_reason`; same `request_id` as the `pod.exec` events |
| `recording.create` failed | Not recorded: reason `disk_quota` (disk policy `stop`) or `error` (e.g. directory not writable) |
| `recording.view` / `recording.download` | An admin played or downloaded a recording |
| `recording.delete` (success / denied / failed) | Delete from the UI / API — records the recording's `owner`, `started_at`, `size_bytes`, `pod`, `container` and cluster, since the row and file are gone afterwards |
| `settings.update` on `recording` | Settings change |
| `recording.evict` / `recording.purge` | Disk-policy eviction / retention purge (user `system`) |

**API (admin only)**
- `GET /api/admin/recordings?user=&namespace=&pod=&cluster=&from=&to=&limit=&offset=` → `{items, total}`
- `GET /api/admin/recordings/{id}` — metadata
- `GET /api/admin/recordings/{id}/cast` — `application/x-asciicast` (`?download=1` for an attachment)
- `DELETE /api/admin/recordings/{id}`
- `GET` / `PUT /api/admin/recordings/settings` — settings (+ disk usage on GET)

# Deployment & workload write actions

OpenConsole can restart, scale, and apply YAML to workloads when the caller has been granted the matching application-level permissions:

| Permission                   | Endpoint                                                                 |
|------------------------------|--------------------------------------------------------------------------|
| `deployments:restart`        | `POST /api/namespaces/{ns}/deployments/{name}/restart`                   |
| `deployments:scale`          | `POST /api/namespaces/{ns}/deployments/{name}/scale` body `{"replicas"}` |
| `statefulsets:scale`         | `POST /api/namespaces/{ns}/statefulsets/{name}/scale` body `{"replicas"}` |
| `{resource}:edit`            | `POST /api/namespaces/{ns}/{resource}/{name}/apply` body `{"yaml","dryRun"}` |

The `edit` action covers Pod, Deployment, DaemonSet, StatefulSet, HPA, Service, ConfigMap, Ingress, CronJob, Job — same handler for all, powered by the `dynamic` client with GVK fallback and server-side `DryRun=All`.

- Every call records an audit event (`deployment.restart`, `deployment.scale`, `statefulset.scale`, `<kind>.apply`) with outcome `success`, `denied`, `rate_limited` or `failed`. Restart records `restarted_at`, scale `replicas_from` / `replicas_to`, apply `dry_run` and the `yaml_from` / `yaml_to` hashes; a failure has a `reason` (`k8s_forbidden`, `not_found`, `conflict`, `invalid`, …) and the `error`.
- Per-user rate limit: 5 burst, 1 token every 6 s. 429 with `Retry-After` when exceeded.
- Scale accepts replicas between 0 and `MAX_REPLICAS` (env, default 100).
- YAML apply enforces optimistic concurrency via `metadata.resourceVersion` — a stale edit returns 409.
- Error mapping: the API server's `apierrors` reason maps to the right HTTP status (NotFound → 404, Conflict → 409, Invalid → 400, Timeout → 504) so a reverse proxy / Cloudflare doesn't wrap a 5xx around a 4xx issue.

Request / audit correlation: every HTTP response carries `X-Request-Id`; the same id appears in the structured request log and in the audit mirror.

# Sessions (Admin → Sessions)

Every issued token lives in `session_tokens` and is checked on every request.

- List all sessions, filter "Only active".
- Revoke a single session, or revoke every session for a user.
- Change-password revokes every session the user has (including the browser that initiated the change).
- Rolling upgrades don't log everyone out — JWTs issued before 2.3.0 are honoured until their natural expiry.
- Audit entries: `session.revoke` (one session, or `all: true` for every session of a user).

# Keyboard shortcuts

Open the full cheat sheet with `?`. The core set:

- Global: `⌘K` / `Ctrl+K` command palette, `?` cheat sheet, `Esc` close active modal.
- Navigate: `g d` → Dashboard, `g a` → Admin.
- Theme: `t l` light, `t d` dark, `t s` system.
- Dashboard: `[` / `]` (or `ğ` / `ü` on a TR Q layout) previous / next resource tab, `r` refresh, `/` (or `.`) focus the search box, `n` focus the namespace filter, `e` toggle Live Events, `c` open the cluster switcher, `v` open Saved Views.
- Cluster switcher / Saved Views when open: `1`–`9` pick by index, `↑/↓` move focus, `Enter` activate, `Esc` close.
- Admin tables (Users, Groups, Roles, Sessions, Recordings): `j` / `k` next / previous row (across pages), `Enter` open the row (edit / play), `d` its delete action (always asks first), `n` / `p` next / previous page, `Esc` clear the selection. Clicking anywhere clears it too.

# Internationalization

- English (`en`) and Turkish (`tr`) ship in the box.
- Locale switcher: compact `EN / TR` chip pair in the header, and a copy on the LoginPage pinned top-right.
- Resolution order: user preference in localStorage → `navigator.language` prefix → `en`. The user override persists across refreshes.

# Security notes

- Grant each verb (`patch`, `update`, `pods/exec`, `pods/log`) only if the matching application permission will actually be handed to at least one role.
- OpenConsole's ServiceAccount should never be granted more than the actions the UI will expose. Port-forward is not used. `secrets` get / list is only needed for the Secrets tab; drop that rule if you won't grant any `secrets:*` permission.
- `secrets:reveal`, `secrets:edit` and `pods:exec` are the permissions that expose credentials. Grant them narrowly and review the `secret.reveal`, `secret.view_yaml`, `secret.apply` and `pod.exec` audit events.
- Token rotation is recommended (every 6–12 months).
- Do not store generated tokens in Git.
- Prefer one ServiceAccount per cluster.
- OpenConsole does not bypass Kubernetes RBAC; it operates strictly within the permissions granted to its ServiceAccount.

## Recommended production pattern

- One ServiceAccount per cluster (`deploy/rbac.yaml`), added with its own token — never personal credentials.
- Store tokens securely.
- Rotate periodically.
- Avoid using personal user credentials.

---

# Using OpenConsole

A walk-through of everything an admin sets up, followed by what users do day to day.

## First login

On the very first start a default admin is created: **`admin` / `admin`**. You must change the password at first login. Admin pages stay locked until you do.

## Admin setup checklist

1. **Admin → Clusters**: add your clusters ([Connecting clusters](#connecting-clusters)) and **Set as default** on one of them.
2. **Identity**: local users ([Users](#users)), [LDAP / Active Directory](#ldap--active-directory) and / or [Azure AD](#azure-ad-entra-id).
3. **Access**: groups, roles and permissions ([Groups, roles and permissions](#groups-roles-and-permissions)).
4. Optional: [Recording settings](#session-recording), [session timeout](#session-timeout), [logo](#customization).

## Users

**Admin → Users** lists every account with its **Source**:

| Source | How the user signs in | Password managed |
|---|---|---|
| Local | username + password stored in OpenConsole (bcrypt) | in OpenConsole |
| LDAP | directory username + directory password | in the directory |
| Azure AD | "Sign in with Microsoft" | in Azure AD / Entra ID |

- **New user** creates an account. When LDAP or Azure AD is enabled it opens a menu:
  - **Local user**: the admin sets the first password.
  - **Import from LDAP…**: the same search-and-import panel as Admin → LDAP ([below](#ldap--active-directory)).
  - **Azure AD user**: pre-creates a Microsoft account with no password, by the person's UPN or e-mail address (e.g. `jane@example.com`). Their first "Sign in with Microsoft" uses it.

  The main part of the button opens the local-user form directly; the arrow opens the menu. Pick **Groups** right away, and tick **Admin** for full access. New accounts are listed first and highlighted for a moment. Non-admins see nothing until they are in a group with a role ([below](#groups-roles-and-permissions)).
- **The source decides how a password is checked.** Local accounts use their OpenConsole password. LDAP accounts are checked against the directory only, and Azure AD accounts never accept a password (they use the Microsoft button), so a stray local password can't bypass the directory. A failed sign-in always gets the same answer, so the login form doesn't reveal whether an account exists or where it signs in; the failed `user.login` audit event records the reason.
- **Edit** (pencil): admin flag, active / disabled, group membership. A disabled user is signed out on the next request.
- **Reset password** (key icon, **local users only**): sets a new password (min. 8 characters, see `PASSWORD_MIN_LENGTH`) and by default forces a change at next login. All of that user's sessions are signed out, and the reset is audited as `user.reset_password`. LDAP and Azure AD users have no reset here: their password lives in the directory, and a local one would let them bypass it.
- Users change their own password from the header menu. Doing so signs out all their other sessions.
- **Accounts from before 2.13** start out as Local. LDAP accounts switch to LDAP on their next directory sign-in. To fix sources up front (for example for users who haven't signed in since), update the database directly. Stop the app, since the volume is ReadWriteOnce and the image has no `sqlite3`:

  ```bash
  NS=kubernetes-openconsole
  kubectl -n $NS scale deploy/kubernetes-openconsole --replicas=0
  kubectl -n $NS wait --for=delete pod -l app=kubernetes-openconsole --timeout=120s
  kubectl -n $NS run oc-sql --rm -it --restart=Never --image=alpine:3.20 --overrides='{"spec":{"containers":[{"name":"oc-sql","image":"alpine:3.20","stdin":true,"tty":true,"command":["sh","-c","apk add -q sqlite && cp /data/app.db /data/app.db.bak-$(date +%s) && sqlite3 /data/app.db"],"volumeMounts":[{"name":"data","mountPath":"/data"}]}],"volumes":[{"name":"data","persistentVolumeClaim":{"claimName":"kubernetes-openconsole-data"}}]}}'
  ```

  ```sql
  SELECT username, auth_source FROM users ORDER BY auth_source, username;
  -- Azure AD: everyone with a Microsoft sign-in in the audit log (kept LOG_RETENTION_DAYS)
  UPDATE users SET auth_source = 'azure' WHERE auth_source = 'local'
     AND username IN (SELECT DISTINCT user FROM audit_logs WHERE action = 'user.login'
       AND (details LIKE '%"login_method":"azure"%' OR resource_name LIKE 'azure_ad%'));
  -- By name
  UPDATE users SET auth_source = 'azure' WHERE username IN ('jane@example.com');
  UPDATE users SET auth_source = 'ldap'  WHERE username IN ('john', 'ayse.yilmaz');
  .quit
  ```

  Then `kubectl -n $NS scale deploy/kubernetes-openconsole --replicas=1`. The command above keeps a backup next to the database. To turn an account back into a local one, set `auth_source = 'local'` and give it a password with **Reset password**.
- **Delete** removes the account and its group memberships. The last active admin can't be deleted or demoted.
- **Export CSV** (Users and Groups tabs): users with source, admin / active flags and groups; groups with members and roles. Handy for periodic access reviews. Each export is audited as `admin.export`.

## LDAP / Active Directory

LDAP works alongside local accounts. By default users must exist in OpenConsole before they can sign in, so you **import** them. Alternatively, turn on **Create an account on a user's first sign-in** ([below](#accounts-on-first-sign-in)) and skip importing.

**1. Configure** (Admin → LDAP):

| Field | Meaning |
|---|---|
| Enabled | turns LDAP sign-in on or off |
| URL *or* Host + Port | `ldap://dc01.example.corp:389` or `ldaps://…:636`; or fill Host / Port / **Use SSL** instead |
| StartTLS | upgrade a plain `ldap://` connection to TLS |
| Skip TLS certificate verification | only for testing; leave it off in production |
| Timeout | seconds per LDAP operation (default 10) |
| Bind DN / Bind password | service account used to search the directory, e.g. `CN=svc-openconsole,OU=ServiceAccounts,DC=example,DC=corp`. The password is stored encrypted; tick **Update Bind Password** only when changing it. |
| User base DN (+ additional base DNs) | where users are searched, one DN per line for several OUs |
| User filter | LDAP filter with `%s` for the typed name. AD: `(sAMAccountName=%s)`, or `(sAMAccountName=%s*)` for prefix search in the import box. OpenLDAP: `(uid=%s)`. |
| Username attribute | the attribute that becomes the OpenConsole username: `sAMAccountName` (AD) or `uid` (OpenLDAP) |

**Save LDAP settings**, then **Test connection**. The test binds with the service account and runs a search in each base DN.

**2. Import users**: from **Admin → Users → New user → Import from LDAP…**, or under the settings on Admin → LDAP. Type part of a name and search; the user filter is applied with `%s` replaced by what you typed, and results are capped at 100 per base DN. Users who already have an account are listed separately and can't be picked again. Pick the users, optionally pick **groups** to add them to, and import. Imported accounts get source **LDAP** and no usable local password. Users who already exist are skipped and reported. The `admin.import` audit entry names the imported users.

**3. Give them access**: if you didn't pick groups during the import, add the users to groups (Admin → Users → edit, or Admin → Groups). Until then they can sign in but see no namespaces.

**4. Sign-in**: users type their directory username and password on the normal login form. OpenConsole finds their DN with the user filter and binds as them. A wildcard filter (`%s*`) is safe here: at login, OpenConsole additionally requires an exact match on the username attribute, so `jo` can never resolve to `john`. Turning **Enabled** off stops all LDAP sign-ins immediately.

### Accounts on first sign-in

Off by default. In **Admin → LDAP**, tick **Create an account on a user's first sign-in**, optionally pick **groups for new accounts**, and save. From then on:

- Someone without an account who signs in with valid directory credentials gets an LDAP account on the spot, under the name the directory uses (typing `John` signs in to `john`). The account is added to the chosen groups, so it can see something right away.
- Anyone the **user filter** finds under the base DNs can sign in. To allow only one directory group, put it in the filter, e.g. `(&(sAMAccountName=%s)(memberOf=CN=OpenConsole Users,OU=Groups,DC=example,DC=corp))`.
- New accounts are never admins. Each one is audited as `user.create` with `auto_provisioned: true`.
- **To lock someone out, disable their account; don't delete it.** A deleted account is created again on the next sign-in, while a disabled one stays disabled.
- Unknown users with a wrong password are rejected as before; nothing is created.

> Example (anonymized) Active Directory setup: Host `10.10.20.15`, Port `389`, Bind DN `CN=svc-openconsole,OU=ServiceAccounts,OU=IT,DC=example,DC=corp`, User base DN `OU=Engineering,OU=Users,DC=example,DC=corp`, User filter `(sAMAccountName=%s)`, Username attribute `sAMAccountName`.

## Azure AD (Entra ID)

Single-tenant sign-in that works alongside local / LDAP accounts.

**1. App registration** (Azure portal → Entra ID → App registrations → New):
- Supported account types: **single tenant**.
- Redirect URI (Web): `https://<your-openconsole-host>/api/auth/azure/callback`.
- Certificates & secrets → new **client secret**.
- Scopes used: `openid profile email`; no extra API permissions are needed.

**2. Configure** (Admin → Azure AD): **Enabled**, **Tenant ID**, **Client ID**, **Client secret** (stored encrypted; leave it empty to keep the stored one) and **Redirect URL** (the same URI as above). Save, then **Test configuration**.

**3. Sign-in**: the login page shows **Sign in with Microsoft**. On a user's first successful sign-in, the account is created automatically with source **Azure AD**. The username is the token's `preferred_username`, or `email` / `upn` if that is missing.

**4. Give them access**: add the new user to groups after their first sign-in. Or, better, set them up in advance: **Admin → Users → New user → Azure AD user**, enter their UPN or e-mail address (e.g. `jane@example.com`) and pick the groups. The first Microsoft sign-in then uses that account.

How the account is found on sign-in:
- First by `preferred_username`, which is usually the UPN.
- If there's no exact match, OpenConsole looks for a **pre-created Azure AD account that nobody has signed in to yet** whose name matches `preferred_username` in another letter case, or the token's `email` or `upn` claim. That covers a pre-created `jane.doe@corp.com` when the UPN is `jdoe@corp.onmicrosoft.com`.
- Local, LDAP and already used accounts are never claimed this way. The `user.login` audit event notes when an account was claimed (`linked_by`, `signed_in_as`).

Signing out of OpenConsole does not sign the user out of Microsoft.

## Groups, roles and permissions

Access is **User → Group → Role → Permission**. Admins bypass all of it.

- **Role**: a named set of permissions, e.g. `payments-developer`.
- **Permission**: cluster (one, or **All clusters**) + namespace + resource + action. The full list is in [Application permissions](#application-permissions).
- **Group**: a set of users; a group gets one or more roles.

Typical flow:
1. **Admin → Roles → New role**, then **Add permissions**. Pick the cluster, one or more namespaces (multi-select with filter, "Select N matching"), and a template (Viewer / Developer / SRE / Admin) or individual actions. **Copy from role** clones another role's grants. Existing grants are shown as cards per namespace and can be edited in place.
2. **Admin → Groups → New group**, then assign the role(s).
3. Add users to the group (from the group, or from Admin → Users).

Changes apply on the user's next request; no sign-out is needed. A user only sees namespaces where they have at least one permission on their current cluster.

## Choosing your cluster

Every user works on **their own** cluster:

- The header switcher (or the `c` key) lists the clusters your permissions cover; admins see all. Picking one switches **only you**, and the choice is remembered across sessions and devices.
- Until you pick one, you work on the **default** cluster, marked "default" in the list. Admins set it under Admin → Clusters → **Set as default**.
- If your cluster is deleted or you lose all permissions on it, you fall back to the default automatically.
- Every audit entry records which cluster the action ran against. Admin → Audit Logs shows it, and the CSV export has a `cluster` column.

## Day-to-day use (Dashboard)

- **Namespaces** (left panel): only the ones you have access to, with a filter (`n`). The selection is remembered.
- **Resource tabs**: only the resources you may list. `[` / `]` switch tabs. There are **card** and **list** views; list columns are sortable.
- **Search** (`/`): name tokens plus `label:key=value` or `label:key`, combined with AND.
- **Saved views** (`v`): save the current cluster + namespace + tab + search + view mode under a name. Views are stored on the server, so they follow you to every browser. Opening a view saved on another cluster switches you to that cluster. The share icon makes a view visible to **every user** (marked with its owner); others can use it but only you can rename, unshare or delete it, and admins can remove shared views. A shared view never grants access: someone without permission on its namespace just sees an empty list. Views saved in the browser by older versions are moved to the server the first time you open the menu.
- **Live Events** (`e`): adds, updates, deletes and Kubernetes Events in real time, with filters for warnings.
- **Pods**: logs (live stream), events, **Shell** (`pods:exec`, recorded), YAML.
- **Deployments / StatefulSets**: restart, scale, logs across all pods, YAML edit with server dry-run and a diff before apply.
- **ConfigMaps**: data view; **Secrets**: keys, reveal and edit ([Secrets](#secrets)).
- `⌘K` / `Ctrl+K` opens the command palette; `?` lists every shortcut.

## Admin tools

- **Audit Logs**: every read and write action with user, outcome, cluster, namespace and resource; **Details** on a row shows its details, reason, source IP, account source, request id and user agent ([Audit events](#audit-events)). Retention: `LOG_RETENTION_DAYS`. The CSV export uses the same filters as the screen and has a column per field (details as JSON). Filters:
  - **User**, **Action** and **Namespace** suggest the values that actually occur in the log as you type. Typed text matches anywhere.
  - Picking an action matches it exactly. Its family row, e.g. `pod.*`, selects everything done to pods.
  - **Outcome** (success / denied / failed / rate_limited / locked), **Verb** (list, restart, exec, …), **Resource type** and **Cluster** narrow any of them, e.g. "everything denied", or `secret.*` + denied.
- **Users / Groups → Export CSV**: who has access and through which group and role.
- **Sessions**: every issued token; revoke one or all of a user's ([Sessions](#sessions-admin--sessions)).
- **Recordings**: replay, download (with a warning) or delete pod shell sessions, and set retention / disk limits ([Session Recording](#session-recording)).

### Session timeout

**Admin → Session**: how long a login token stays valid (minutes, default 60). This applies to new logins.

### Customization

**Admin → Customization**: upload a PNG or SVG logo (up to 256 KB), shown in the header and on the login page. Remove it to go back to the default mark.

## Tips & gotchas

- **Cluster connection is UI-only**. No env vars, mounted kubeconfigs or in-cluster ServiceAccount auto-detection are used by the backend: add even the local cluster in Admin → Clusters.
- **Namespace visibility is permission-based**; if a user sees nothing, check role permissions.
- If LDAP bind password is already configured, toggle **Update Bind Password** only when actually changing it.
- Audit log filters combine user / action / outcome / namespace / date range.
- Pod logs stream via WebSocket; verify connectivity from the backend pod to the API server.
- The YAML modal is read-only by default — the Edit button only appears when the viewer has `{resource}:edit`.
- Monaco loads from `cdn.jsdelivr.net`. In air-gapped deployments, self-host the `vs` folder and point `@monaco-editor/react`'s `loader.config({ paths: { vs: '/vs' } })` at the local path, then tighten CSP back to `self`.

---

Kubernetes OpenConsole is designed as an internal visibility and operations platform and is **not** a Kubernetes security boundary.
