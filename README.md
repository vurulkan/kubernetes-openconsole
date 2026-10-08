# Kubernetes OpenConsole

Modern, production-ready Kubernetes visibility and operations console with strict application-level authorization. Runs inside Kubernetes, reads cluster data using a single ServiceAccount identity per cluster, and enforces every access decision in the app layer (not via Kubernetes RBAC).

## Highlights

### Observability & live data
- **Informer-driven lister cache** — list endpoints read from a `client-go` SharedInformerFactory, so the UI is instant and the API server isn't hammered by polling.
- **Live Events side panel** — streams `added` / `updated` / `deleted` plus native `corev1.Event` objects over a WebSocket. Filter by All / K8s events / Warnings.
- **Prometheus `/metrics`**, dedicated `/livez` (process) and `/readyz` (DB + kube client) endpoints.

### Workloads shown in the Dashboard
Pods, Deployments, **DaemonSets**, **StatefulSets**, **HorizontalPodAutoscalers (v2)**, Services, ConfigMaps, Ingresses, CronJobs, Jobs — card view, list view, label filters, saved views.

### Write operations (opt-in per role, per namespace)
- **Deployment restart** (`deployments:restart`)
- **Deployment / StatefulSet scale** (`deployments:scale`, `statefulsets:scale`)
- **YAML view + edit + server dry-run + apply** for every workload above (`{resource}:edit`), powered by Monaco. Diff view, dry-run returns the server-canonicalized object, optimistic concurrency via `resourceVersion`.
- **Pod shell** (`pods:exec`) over WebSocket with xterm.js.
- **Pod shell session recording** — every shell is saved as an asciicast v2 file and can be replayed by admins (Admin → Recordings) with an in-browser player. See [Session Recording](#session-recording).
- **Pod / Deployment logs** (`pods:logs`) with rate limiting.

Every write action records `{resource}.{action}.{success|denied|failed|rate_limited}` audit entries and the HTTP response carries `X-Request-Id` for correlation with the audit mirror in stdout.

### Access & identity
- **User → Groups → Roles → per-cluster, per-namespace permissions** (application-level RBAC, no Kubernetes RBAC for end users).
- **Namespace discovery is permission-based** (no leakage of names you can't access).
- **Multi-cluster** — save N clusters, switch via header dropdown or the `c` keyboard shortcut.
- **Local users** (bcrypt) + **LDAP** (bind-based, searchable + importable) + **Azure AD** single-tenant login — all configurable via UI.
- **JWT authentication** with forced password change on first login.
- **Session management** (Admin → Sessions): list every active token, revoke individual sessions or every session for a user, change-password revokes everything.
- **Session recordings** (Admin → Recordings): filter, replay (1x / 2x / 4x, seek, skip idle), download `.cast`, delete; retention, quota and on/off switch editable in the UI.
- **Login brute-force protection** (5 fails per IP+user → 5-minute lock, audited).

### UX
- **Light / Dark / System theme** (persisted; respects OS).
- **Internationalization — English & Turkish** (locale switcher next to the theme toggle; defaults to browser language, persists user override). TR covers nav, Dashboard, Admin, audit, keyboard cheat sheet.
- **Keyboard-first navigation**: `⌘K` / `Ctrl+K` command palette, `?` cheat sheet, chord shortcuts for nav/theme, `c` cluster switcher, `v` saved views, `e` live events panel, `n` namespace filter focus. TR keyboard positions (`ğ` / `ü` / `.`) are mapped to the US `[` / `]` / `/` by physical key, so the shortcuts don't break on a TR Q layout.
- **Saved views** — persist (namespace, tab, search, viewMode) under a name in localStorage.
- **Label filters in the search box** — `label:app=foo`, `label:tier`, name tokens, AND-combined.
- **Audit logs** with pagination, filters, CSV export.
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
image: ghcr.io/vurulkan/kubernetes-openconsole:latest   # or :2.9.0 to pin
```

Published tags: `latest`, `2.0.0`, `2.1.0` → `2.9.0`. Always pin a specific version in production.

## Run (local Docker, no cluster)

```bash
docker run --rm -p 8080:8080 \
  -e DATA_PATH=/data/app.db \
  -e STATIC_DIR=/app/public \
  -e TIMEZONE=Europe/Istanbul \
  -e LOG_FORMAT=json \
  -e LOG_LEVEL=info \
  -e LOG_INCLUDE_AUDIT=true \
  -e MAX_REPLICAS=100 \
  -v kubernetes-openconsole-data:/data \
  ghcr.io/vurulkan/kubernetes-openconsole:latest
```

> Ephemeral storage: drop the volume and set `DATA_PATH=/tmp/app.db`.

## Kubernetes deploy

```bash
kubectl apply -f deploy/namespace.yaml
kubectl apply -f deploy/pvc.yaml
kubectl apply -f deploy/deployment.yaml
kubectl apply -f deploy/service.yaml
# then the ServiceAccount + ClusterRole + binding (see "Kubernetes API Access" below)
```

The shipped `deploy/deployment.yaml` carries the recommended env, resource requests / limits, `/livez` liveness, `/readyz` readiness, and runs as non-root with `seccompProfile: RuntimeDefault`.

## Environment variables

### Core
- `DATA_PATH` (default `/data/app.db`) — SQLite DB location.
- `STATIC_DIR` (default `/app/public`) — Served React build output.
- `TIMEZONE` (default `UTC`) — Used for audit log timestamps.
- `LOG_RETENTION_DAYS` (default `30`) — Audit log retention (purged automatically).
- `MAX_REPLICAS` (default `100`) — Hard upper bound the Scale endpoint accepts for Deployment / StatefulSet scaling.

### Session recording
These **seed** the recording settings on first boot only; afterwards Admin → Recordings owns them (except `SESSION_RECORDING_DIR`, read on every start). See [Session Recording](#session-recording).

- `SESSION_RECORDING_ENABLED` (default `true`) — record new pod shell sessions.
- `SESSION_RECORDING_DIR` (default `<dir of DATA_PATH>/recordings`, i.e. `/data/recordings`) — where `.cast` files are written.
- `SESSION_RECORDING_RETENTION_DAYS` (default `30`, `0` = never purge) — daily purge of older recordings.
- `SESSION_RECORDING_MAX_SIZE_MB` (default `10`) — per-session cap; past it the recording stops and is flagged truncated.
- `SESSION_RECORDING_MAX_TOTAL_MB` (default `2048`) — quota for all recordings together.
- `SESSION_RECORDING_MIN_FREE_MB` (default `512`) — free space always left on the recordings volume.
- `SESSION_RECORDING_DISK_POLICY` (default `evict_oldest`) — `evict_oldest` or `stop`; see below.

### Structured logging (slog)
Logs go to stdout via Go's `log/slog`. In production set `LOG_FORMAT=json` so Filebeat / Fluent Bit / Vector can ship them directly to Elastic / Kibana / Loki.

- `LOG_LEVEL` (default `info`) — `debug` | `info` | `warn` | `error`.
- `LOG_FORMAT` (default `text`) — `text` for humans, `json` for log shippers.
- `LOG_OUTPUT` (default `stdout`) — `stdout` | `stderr`.
- `LOG_ADD_SOURCE` (default `false`) — include `file:line` in every record.
- `LOG_INCLUDE_AUDIT` (default `true`) — mirror DB audit entries to stdout with event name `audit`. Each audit line carries `request_id` so you can join it to the matching `http.request` entry in Elastic.
- `APP_ENV`, `APP_VERSION` — optional static labels attached to every log record.

Example JSON record (`LOG_FORMAT=json`):

```json
{"time":"2026-10-05T08:14:05Z","level":"INFO","msg":"audit",
 "service":"openconsole","event":"deployment.scale.success",
 "user":"mustafav","namespace":"payments","resource_type":"deployment",
 "resource_name":"nginx (from=3 to=5)",
 "request_id":"qXpB6yXONDiuXKX2"}
```

Every HTTP response also carries an `X-Request-Id` header matching the `request_id` field.

### Azure AD OAuth (only if used)
Configured through **Admin → Azure AD** at runtime — no env vars.

### LDAP (only if used)
Configured through **Admin → LDAP** at runtime — no env vars.

---

# Kubernetes API Access (ServiceAccount setup)

OpenConsole runs with a single cluster identity and enforces authorization strictly at the application layer. It does **not** act as a Kubernetes security boundary — it only reflects the permissions granted to its ServiceAccount.

> ⚠️ **Quick Start (In-Cluster)**
>
> When OpenConsole runs inside the same cluster it monitors, it uses the mounted ServiceAccount token automatically. You can skip the kubeconfig steps below and go straight to **[First Login](#first-login)**.
>
> Not recommended for production: create a **dedicated** ServiceAccount with a minimally-scoped ClusterRole below rather than reusing `default`.

## 1. Create the ServiceAccount

```bash
kubectl create serviceaccount openconsole-reader -n kubernetes-openconsole
```

## 2. Create the ClusterRole

Covers everything the Dashboard needs today, including the YAML edit flow (`update`), scale (`.../scale: update`), restart (`deployments: patch`), pod exec, pod logs, and the informer `watch`.

Create `openconsole-clusterrole.yaml`:

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: openconsole-readonly
rules:
  # Core API group — reads (list for everything the Dashboard tabs show,
  # plus events for the Live Events panel).
  - apiGroups: [""]
    resources:
      - namespaces
      - pods
      - services
      - configmaps
      - events
    verbs: ["get", "list", "watch"]

  # Pod logs (pods:logs application permission).
  - apiGroups: [""]
    resources:
      - pods/log
    verbs: ["get"]

  # Pod shell (pods:exec application permission). Omit if you'll never
  # grant pods:exec.
  - apiGroups: [""]
    resources:
      - pods/exec
    verbs: ["create"]

  # Writes on core resources, for the YAML apply flow ({resource}:edit).
  # Omit `update` on any resource whose edit permission you'll never grant.
  - apiGroups: [""]
    resources:
      - pods
      - services
      - configmaps
    verbs: ["update"]

  # apps/v1 workloads.
  - apiGroups: ["apps"]
    resources:
      - deployments
      - daemonsets
      - statefulsets
    verbs: ["get", "list", "watch"]

  # deployments writes: patch for restart, update for YAML apply.
  - apiGroups: ["apps"]
    resources:
      - deployments
    verbs: ["patch", "update"]

  # daemonsets / statefulsets YAML apply.
  - apiGroups: ["apps"]
    resources:
      - daemonsets
      - statefulsets
    verbs: ["update"]

  # Scale subresource (deployments:scale + statefulsets:scale).
  - apiGroups: ["apps"]
    resources:
      - deployments/scale
      - statefulsets/scale
    verbs: ["get", "update"]

  # HorizontalPodAutoscaler v2 — the Dashboard renders metrics from v2.
  - apiGroups: ["autoscaling"]
    resources:
      - horizontalpodautoscalers
    verbs: ["get", "list", "watch", "update"]

  # Ingress.
  - apiGroups: ["networking.k8s.io"]
    resources:
      - ingresses
    verbs: ["get", "list", "watch", "update"]

  # Batch.
  - apiGroups: ["batch"]
    resources:
      - cronjobs
      - jobs
    verbs: ["get", "list", "watch", "update"]
```

Apply:

```bash
kubectl apply -f openconsole-clusterrole.yaml
```

## 3. Bind ClusterRole → ServiceAccount

```bash
kubectl create clusterrolebinding openconsole-readonly-binding \
  --clusterrole=openconsole-readonly \
  --serviceaccount=kubernetes-openconsole:openconsole-reader
```

## 4. Reference the ServiceAccount in the Deployment

Already set in `deploy/deployment.yaml`:

```yaml
spec:
  template:
    spec:
      serviceAccountName: openconsole-reader
```

## 5. (Only for out-of-cluster use) Generate a token + minimal kubeconfig

If OpenConsole runs outside the cluster it monitors, create a long-lived token and feed a kubeconfig into **Admin → Clusters** at the UI.

```bash
kubectl create token openconsole-reader \
  -n kubernetes-openconsole \
  --duration=8760h    # 1 year; adjust as needed
```

Minimal kubeconfig:

```yaml
apiVersion: v1
kind: Config
clusters:
- name: target-cluster
  cluster:
    server: https://YOUR_API_SERVER
    certificate-authority-data: YOUR_CA_DATA
users:
- name: openconsole-reader
  user:
    token: YOUR_GENERATED_TOKEN
contexts:
- name: openconsole-context
  context:
    cluster: target-cluster
    user: openconsole-reader
current-context: openconsole-context
```

---

# Pod Shell (exec)

Interactive shell into a running container, gated by application permission `pods:exec`. Off by default on every role; admins opt in per role, per namespace.

- Endpoint: `GET /ws/namespaces/{namespace}/pods/{name}/exec?container=<c>&command=/bin/sh` (WebSocket).
- xterm.js UI with container picker on multi-container pods and shell picker (`/bin/sh`, `/bin/bash`, `/bin/ash`).
- Idle timeout: **5 minutes** without stdin automatically closes the session.
- Each session logs `pod.exec.start` and `pod.exec.end` (with duration and outcome) to both the audit DB and the structured console log.
- Terminal output is recorded by default — see [Session Recording](#session-recording).
- ClusterRole must grant `pods/exec: create` for this to work.

**Security notes**
- Exec is the highest-risk action in OpenConsole; grant it narrowly.
- Non-root pod admission policies in your cluster still apply.

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
- ⬇ downloads the `.cast` file. It plays in the `asciinema` CLI too: `asciinema play file.cast`.
- 🗑 deletes the file and its row. A recording whose session is still running can't be deleted.

**Settings (Admin → Recordings → Recording settings).** On/off, retention, per-session cap, total quota, free-space floor and disk policy. Changes apply to new sessions immediately, with no restart; a running session keeps the limits it started with. Lowering the retention triggers a purge right away.

**Disk protection.** By default recordings share the PVC with `app.db`. If that volume filled up, SQLite could no longer write, and login and audit would break with it. Two limits prevent this. Both are checked before every new session and every 30 s while sessions are running:

| Limit | Default | Meaning |
|---|---|---|
| Total quota | 2048 MB | All recordings together, plus room for one more full-size session |
| Free-space floor | 512 MB | Always left free on the recordings volume |

When a limit would be crossed, the **disk policy** decides what happens:

- `evict_oldest` (default) — the oldest finished recordings are deleted, even before their retention ends, until the next session fits. Each eviction is audited as `recording.evicted`.
- `stop` — existing recordings are kept. New shells still open but are **not** recorded (`pod.exec.session.record_skipped`), and running recordings stop with a truncation marker. The admin screen shows a warning until space is freed.

The shell itself is never blocked by recording: a disabled, full or broken recorder only means the session isn't recorded. For full isolation, give recordings their own PVC; `deploy/pvc.yaml` and `deploy/deployment.yaml` contain a commented example. Then set `SESSION_RECORDING_DIR=/recordings`.

**Retention.** A background job runs one minute after start and then daily. It deletes recordings older than the retention period (row and file, audited as `recording.purge`) and removes stray `.cast` files that have no database row. If the process crashes mid-session, the next start closes the open row using the file's size and modification time.

**Audit events**

| Event | When |
|---|---|
| `pod.exec.session.recorded` | Session end — `session_id`, `size`, `dur_ms`, truncation reason; same `request_id` as `pod.exec.start` / `end` |
| `pod.exec.session.record_skipped` | Disk policy `stop` refused to record |
| `pod.exec.session.record_failed` | Recorder error (e.g. directory not writable) |
| `recording.view` / `recording.download` | An admin played or downloaded a recording |
| `recording.delete.{success,denied,failed}` | Delete from the UI / API |
| `recording.settings.update.{success,denied,failed}` | Settings change |
| `recording.evicted` / `recording.purge` | Disk-policy eviction / retention purge (user `system`) |

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

- Every call records an audit entry — `success`, `denied`, `rate_limited`, `failed` outcomes.
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
- Audit entries: `session.revoke`, `session.revoke_all`.

# Keyboard shortcuts

Open the full cheat sheet with `?`. The core set:

- Global: `⌘K` / `Ctrl+K` command palette, `?` cheat sheet, `Esc` close active modal.
- Navigate: `g d` → Dashboard, `g a` → Admin.
- Theme: `t l` light, `t d` dark, `t s` system.
- Dashboard: `[` / `]` (or `ğ` / `ü` on a TR Q layout) previous / next resource tab, `r` refresh, `/` (or `.`) focus the search box, `n` focus the namespace filter, `e` toggle Live Events, `c` open the cluster switcher, `v` open Saved Views.
- Cluster switcher / Saved Views when open: `1`–`9` pick by index, `↑/↓` move focus, `Enter` activate, `Esc` close.

# Internationalization

- English (`en`) and Turkish (`tr`) ship in the box.
- Locale switcher: compact `EN / TR` chip pair in the header, and a copy on the LoginPage pinned top-right.
- Resolution order: user preference in localStorage → `navigator.language` prefix → `en`. The user override persists across refreshes.

# Security notes

- Grant each verb (`patch`, `update`, `pods/exec`, `pods/log`) only if the matching application permission will actually be handed to at least one role.
- OpenConsole's ServiceAccount should never be granted more than the actions the UI will expose — `secrets` access and port-forward are intentionally not used by the app.
- Token rotation is recommended (every 6–12 months).
- Do not store generated tokens in Git.
- Prefer one ServiceAccount per cluster.
- OpenConsole does not bypass Kubernetes RBAC; it operates strictly within the permissions granted to its ServiceAccount.

## Recommended production pattern

- One ServiceAccount per cluster.
- One kubeconfig per cluster (only needed when running outside the cluster you monitor).
- Store tokens securely.
- Rotate periodically.
- Avoid using personal user credentials.

---

## First login

On first startup a default admin is created:

- **username**: `admin`
- **password**: `admin`

You will be forced to change the password on first login.

## Usage

1. Log in as admin.
2. **Admin → Clusters**: add one or more clusters (kubeconfig or token), validate, activate one.
3. **Admin → LDAP / Azure AD**: configure optional identity providers.
4. **Admin → Users / Groups / Roles**: define access. Use the new Role Permissions screen for bulk grants, templates (Viewer / Developer / SRE / Admin), and copy-from-role.
5. **Admin → Sessions**: monitor and revoke tokens.
6. **Admin → Audit Logs**: filter, search, export CSV.

## Example LDAP (Active Directory) config

> Replace with your environment. The example below is anonymized.

- **host**: `10.10.20.15`
- **port**: `389`
- **skip verify**: `false`
- **bind dn**: `CN=svc-openconsole,OU=ServiceAccounts,OU=IT,DC=example,DC=corp`
- **bind password**: `********`
- **user base dn**: `OU=Engineering,OU=Users,DC=example,DC=corp`
- **user filter**: `(sAMAccountName=%s*)`

## Azure AD login (single-tenant, optional)

Azure AD runs in parallel with local / LDAP authentication.

### Behavior

- Configured from **Admin → Azure AD**.
- On first successful Azure AD login, the user is auto-created in the local database.
- RBAC still uses the local model (**Users → Groups → Roles**).
- Logout is application-local only (does not sign the user out of Microsoft globally).

### Required Azure App Registration settings

- **Tenant type**: single tenant
- **Redirect URI**: `https://<your-domain>/api/auth/azure/callback`
- **Scopes used by app**: `openid profile email`

## Tips & gotchas

- **Cluster connection is UI-only**. No env vars or mounted kubeconfigs are consumed by the backend.
- **Namespace visibility is permission-based**; if a user sees nothing, check role permissions.
- If LDAP bind password is already configured, toggle **Update Bind Password** only when actually changing it.
- Audit log filters combine user / action / namespace / date range.
- Pod logs stream via WebSocket; verify connectivity from the backend pod to the API server.
- The YAML modal is read-only by default — the Edit button only appears when the viewer has `{resource}:edit`.
- Monaco loads from `cdn.jsdelivr.net`. In air-gapped deployments, self-host the `vs` folder and point `@monaco-editor/react`'s `loader.config({ paths: { vs: '/vs' } })` at the local path, then tighten CSP back to `self`.

---

Kubernetes OpenConsole is designed as an internal visibility and operations platform and is **not** a Kubernetes security boundary.
