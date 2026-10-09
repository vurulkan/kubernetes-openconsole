# Kubernetes OpenConsole

Modern, production-ready Kubernetes visibility and operations console with strict application-level authorization. Runs inside Kubernetes, reads cluster data using a single ServiceAccount identity per cluster, and enforces every access decision in the app layer (not via Kubernetes RBAC).

## Highlights

### Observability & live data
- **Informer-driven lister cache** — list endpoints read from a `client-go` SharedInformerFactory, so the UI is instant and the API server isn't hammered by polling.
- **Live Events side panel** — streams `added` / `updated` / `deleted` plus native `corev1.Event` objects over a WebSocket. Filter by All / K8s events / Warnings.
- **Prometheus `/metrics`**, dedicated `/livez` (process) and `/readyz` (DB + kube client) endpoints.

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
image: ghcr.io/vurulkan/kubernetes-openconsole:2.12.0   # pin a release
```

CI is the only publisher of image tags (linux/amd64):

| Tag | Built from | Moves? |
|---|---|---|
| `X.Y.Z` (e.g. `2.12.0`) | the `vX.Y.Z` git tag | no — use this in production |
| `latest` | every push to `main` | yes |
| `<full commit sha>` | every push to `main` | no |

Releasing = push the `vX.Y.Z` tag; CI builds and pushes `:X.Y.Z`.

### Tests

CI runs these on every push. Run them locally before you open a PR:

```bash
cd backend && go vet ./... && go test -race ./...    # recorder, exec bridge, RBAC engine, API authorization
cd frontend && npx tsc --noEmit -p . && npm run build
```

The API tests run the real router and SQLite store against client-go's fake clientset. They check that every admin endpoint, namespace / resource / cluster-scoped grant, write action (403 + `denied` audit) and secret reveal is enforced.

## Run (local Docker, no cluster)

```bash
docker run --rm -p 8080:8080 \
  -e TIMEZONE=Europe/Istanbul \
  -v kubernetes-openconsole-data:/data \
  ghcr.io/vurulkan/kubernetes-openconsole:2.12.0
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
| `deployment.yaml` | 1 replica (SQLite on a RWO volume — do not scale out), pinned image, every env var documented inline, requests / limits, `/livez` + `/readyz` probes, non-root, `seccompProfile: RuntimeDefault`, and **no ServiceAccount token mounted** (`automountServiceAccountToken: false`). The app never uses the pod's own identity |

Then:

1. Open the UI and log in as `admin` / `admin` ([First login](#first-login)).
2. Add the cluster in **Admin → Clusters** ([Connecting clusters](#connecting-clusters)). The backend never picks up a cluster on its own.

To upgrade, change the image tag in `deployment.yaml` (or the `images:` override in `kustomization.yaml`) and re-apply.

## Environment variables

### Core
- `DATA_PATH` (default `/data/app.db` in the image) — SQLite DB location. Must be on a persistent volume.
- `STATIC_DIR` (default `/app/public` in the image) — Served React build output.
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

# Connecting clusters

OpenConsole talks to each cluster as one ServiceAccount and enforces per-user access itself (Users → Groups → Roles). The ServiceAccount's ClusterRole is the ceiling: no user can do more than it allows, whatever their role says.

Clusters are added **only in the UI** (Admin → Clusters). Two methods: **ServiceAccount Token** (API server URL + token + CA) or **Kubeconfig** (upload a file). Credentials are validated against the API server before they are saved, and stored encrypted in SQLite. The active cluster is reconnected automatically after a restart.

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

**Save Cluster** validates the connection. Then click **Activate** on the cluster card. Users now see the namespaces their roles allow.

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
- Idle timeout: **5 minutes** without stdin automatically closes the session.
- Each session logs `pod.exec.start` and `pod.exec.end` (with duration and outcome) to both the audit DB and the structured console log.
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
- Every reveal is audited as `secret.reveal.{success,denied,failed}` with the namespace, secret and key name (never the value). It also emits a `secret.action` console line.
- **Editing (`secrets:edit`)**: the YAML shows text values as plain-text `stringData`, so you edit readable values instead of base64. Binary values stay base64 in `data`. On apply Kubernetes merges `stringData` into `data`. Removing a key from the YAML deletes it. The dry-run result comes back in the same shape, so the before / after diff compares like with like.
- The YAML holds every value, so opening it requires `secrets:edit`; `get` or `reveal` is not enough. Each open is audited as `secret.yaml.view.{success,denied,failed}`, and changes as `secrets.apply.{success,denied,rate_limited,failed}`, the same as other resources. Optimistic concurrency applies too: a stale `resourceVersion` gives a 409.
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
| `recording.delete.{success,denied,failed}` | Delete from the UI / API — records the recording's owner, start time, size, cluster and container, since the row and file are gone afterwards |
| `recording.settings.update.{success,denied,failed}` | Settings change |
| `recording.evicted` / `recording.purge` | Disk-policy eviction / retention purge (user `system`) |

Recording actions (view / download / delete) also emit their own `recording.action` console log line with `event`, `user`, `session_id`, `details` and `request_id`, independent of `LOG_INCLUDE_AUDIT`.

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
- OpenConsole's ServiceAccount should never be granted more than the actions the UI will expose. Port-forward is not used. `secrets` get / list is only needed for the Secrets tab; drop that rule if you won't grant any `secrets:*` permission.
- `secrets:reveal`, `secrets:edit` and `pods:exec` are the permissions that expose credentials. Grant them narrowly and review the `secret.reveal.*`, `secret.yaml.view.*`, `secrets.apply.*` and `pod.exec.*` audit entries.
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

## First login

On first startup a default admin is created:

- **username**: `admin`
- **password**: `admin`

You will be forced to change the password on first login.

## Usage

1. Log in as admin.
2. **Admin → Clusters**: add one or more clusters ([Connecting clusters](#connecting-clusters)) and activate one.
3. **Admin → LDAP / Azure AD**: configure optional identity providers.
4. **Admin → Users / Groups / Roles**: define access. Use the new Role Permissions screen for bulk grants, templates (Viewer / Developer / SRE / Admin), and copy-from-role.
5. **Admin → Sessions**: monitor and revoke tokens.
6. **Admin → Audit Logs**: filter, search, export CSV.
7. **Admin → Recordings**: replay pod shell sessions, set retention and disk limits.

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

- **Cluster connection is UI-only**. No env vars, mounted kubeconfigs or in-cluster ServiceAccount auto-detection are used by the backend: add even the local cluster in Admin → Clusters.
- **Namespace visibility is permission-based**; if a user sees nothing, check role permissions.
- If LDAP bind password is already configured, toggle **Update Bind Password** only when actually changing it.
- Audit log filters combine user / action / namespace / date range.
- Pod logs stream via WebSocket; verify connectivity from the backend pod to the API server.
- The YAML modal is read-only by default — the Edit button only appears when the viewer has `{resource}:edit`.
- Monaco loads from `cdn.jsdelivr.net`. In air-gapped deployments, self-host the `vs` folder and point `@monaco-editor/react`'s `loader.config({ paths: { vs: '/vs' } })` at the local path, then tighten CSP back to `self`.

---

Kubernetes OpenConsole is designed as an internal visibility and operations platform and is **not** a Kubernetes security boundary.
