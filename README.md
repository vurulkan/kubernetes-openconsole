# Kubernetes OpenConsole

Modern, production-ready Kubernetes visibility dashboard with strict application-level authorization. Runs inside Kubernetes, reads cluster data using a single ServiceAccount identity per cluster, and enforces access strictly in the app layer (no Kubernetes RBAC for end users).

## Highlights

- **Light / Dark / System theme** (user preference persisted; respects OS)
- **⌘K / Ctrl+K command palette** (quick nav + namespace jump + theme switch)
- **Prometheus `/metrics`**, dedicated `/livez` and `/readyz` endpoints
- **Login brute-force protection** (5 fails per IP+user → 5-minute lock, audited)
- **Security headers** including a strict CSP, `X-Frame-Options`, `Permissions-Policy`
- **Kubernetes visibility** (Pods, Deployments, Services, ConfigMaps, Ingresses, CronJobs)
- **Application-level RBAC**: user → groups → roles → per-namespace permissions
- **Namespace discovery is permission-based** (no leakage)
- **JWT authentication** with forced password change on first login
- **Local users** (bcrypt) + **LDAP auth** (bind-based) + **Azure AD login** configurable via UI
- **Audit logs** with pagination, filters, and CSV export
- **WebSocket pod log streaming** with rate limiting
- **Multi-cluster support** — save N clusters, switch via header, migration-safe
- **Cluster connection management via UI only** (kubeconfig or token)
- **Modern React + TypeScript UI**

## Architecture

- **Backend**: Go + `client-go`. The backend communicates directly with the Kubernetes API server using client-go.
- **Frontend**: React + TypeScript
- **Database**: SQLite
- **Deployment**: Docker + Kubernetes manifests

## Option A: Build Yourself

```bash
cd /path/to/kubernetes-openconsole
docker build -t kubernetes-openconsole:local .
```

## Option B: Use the Prebuilt Image (GHCR)

Update `deploy/deployment.yaml` to use the published image:

```yaml
image: ghcr.io/vurulkan/kubernetes-openconsole:latest
```

## Run (local Docker)

```bash
docker run --rm -p 8080:8080 \
  -e LOG_RETENTION_DAYS=30 \
  -e TIMEZONE=Europe/Istanbul \
  -e DATA_PATH=/data/app.db \
  -e STATIC_DIR=/app/public \
  -v kubernetes-openconsole-data:/data \
  kubernetes-openconsole:local
```

> If you prefer ephemeral storage: set `DATA_PATH=/tmp/app.db` without a volume mount.

## Kubernetes Deploy

Apply manifests in `deploy/`:

```bash
kubectl apply -f deploy/namespace.yaml
kubectl apply -f deploy/pvc.yaml
kubectl apply -f deploy/deployment.yaml
kubectl apply -f deploy/service.yaml
```

## Environment Variables

### Core
- `LOG_RETENTION_DAYS` (default: 30) — Audit log retention in days (purged automatically).
- `TIMEZONE` (default: UTC) — Used for audit log timestamps.
- `DATA_PATH` (default: `/data/app.db`) — SQLite DB location.
- `STATIC_DIR` (default: `/app/public`) — Served React build output.

### Structured logging (slog)
Logs go to stdout via Go's `log/slog`. In production set `LOG_FORMAT=json` so
Filebeat / Fluent Bit / Vector can ship them straight to Elastic/Kibana or Loki.

- `LOG_LEVEL` (default: `info`) — `debug` | `info` | `warn` | `error`
- `LOG_FORMAT` (default: `text`) — `text` for humans, `json` for log shippers
- `LOG_OUTPUT` (default: `stdout`) — `stdout` | `stderr`
- `LOG_ADD_SOURCE` (default: `false`) — include `file:line` in every record
- `LOG_INCLUDE_AUDIT` (default: `true`) — mirror DB audit entries to console
  with event name `audit`, so you get the same records twice: durable in SQLite,
  streamable to your log pipeline
- `APP_ENV` (optional) — label attached to every log record (`env=prod`)
- `APP_VERSION` (optional) — label attached to every log record (`version=1.0.7`)

Example JSON record (`LOG_FORMAT=json`):

```json
{"time":"2026-10-01T10:12:33Z","level":"INFO","msg":"http.request",
 "service":"openconsole","method":"GET","path":"/api/namespaces",
 "status":200,"duration_ms":12,"remote_ip":"10.0.0.4",
 "request_id":"q7Jk8-ab0t","user_agent":"curl/8.4.0"}
```

Each response carries an `X-Request-Id` header matching the `request_id` field,
so request logs, audit events and the client can be correlated end-to-end.

---

# Kubernetes API Access (ServiceAccount Setup)

Kubernetes OpenConsole runs with a single cluster identity and enforces authorization strictly at the application layer.

It does **not** act as a Kubernetes security boundary.  
It only reflects the permissions granted to its ServiceAccount.

Below is the recommended setup using a dedicated ServiceAccount in the `kubernetes-openconsole` namespace.

---

> ⚠️ **Quick Start (In-Cluster Default)**
>
> If OpenConsole is deployed inside the same Kubernetes cluster it will monitor,
> it can automatically use the in-cluster configuration via the mounted
> ServiceAccount token (typically the default ServiceAccount).
>
> In that case, you may skip the kubeconfig generation steps below and proceed directly to:
>
> 👉 **[First Login](#first-login)**
>
> ⚠️ While this works for quick testing, it is **not recommended for production**.
>
> For production environments it is strongly recommended to:
>
> - Create a dedicated ServiceAccount
> - Assign a minimally-scoped ClusterRole (least-privilege for the actions you intend to grant through OpenConsole)
> - Avoid granting permissions to the default ServiceAccount
>
> This reduces blast radius and aligns with least-privilege principles.


## Create ServiceAccount

```bash
kubectl create serviceaccount openconsole-reader -n kubernetes-openconsole
```



## Create ClusterRole (Read-Only + Logs + Events + Namespace List)

Create `openconsole-clusterrole.yaml`:

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: openconsole-readonly
rules:
  - apiGroups: [""]
    resources:
      - namespaces
      - pods
      - services
      - configmaps
      - events
    verbs: ["get", "list", "watch"]

  - apiGroups: [""]
    resources:
      - pods/log
    verbs: ["get"]

  - apiGroups: [""]
    resources:
      - pods/exec
    verbs: ["create"]  # required for the Pod Shell (pods:exec) action; omit if you do not grant that permission

  - apiGroups: ["apps"]
    resources:
      - deployments
    verbs: ["get", "list", "watch", "patch"]  # patch required for rollout restart

  - apiGroups: ["apps"]
    resources:
      - deployments/scale
    verbs: ["get", "update"]  # required for the Scale action

  - apiGroups: ["networking.k8s.io"]
    resources:
      - ingresses
    verbs: ["get", "list", "watch"]

  - apiGroups: ["batch"]
    resources:
      - cronjobs
      - jobs
    verbs: ["get", "list", "watch"]
```

Apply it:

```bash
kubectl apply -f openconsole-clusterrole.yaml
```



## Bind ClusterRole to ServiceAccount

```bash
kubectl create clusterrolebinding openconsole-readonly-binding \
  --clusterrole=openconsole-readonly \
  --serviceaccount=kubernetes-openconsole:openconsole-reader
```



## Generate Access Token (Kubernetes 1.24+)

```bash
kubectl create token openconsole-reader \
  -n kubernetes-openconsole \
  --duration=8760h
```

> 8760h = 1 year. Adjust as needed.



## Create Minimal kubeconfig

```yaml
apiVersion: v1
kind: Config
clusters:
- name: target-cluster
  cluster:
    server: https://YOUR_API_SERVER # from your kubeconfig
    certificate-authority-data: YOUR_CA_DATA # from your kubeconfig
users:
- name: openconsole-reader
  user:
    token: YOUR_GENERATED_TOKEN # previous step
contexts:
- name: openconsole-context
  context:
    cluster: target-cluster
    user: openconsole-reader
current-context: openconsole-context
```



## Add serviceAccount to deployment
```yaml
...
    metadata:
      labels:
        app: kubernetes-openconsole
    spec:
      serviceAccountName: openconsole-reader # -> add this line
      securityContext:
        runAsNonRoot: true
...
```

# Pod Shell (exec)

Interactive shell into a running container, gated by application permission
`pods:exec`. Off by default on every role; admins opt in per role, per namespace.

- `GET /ws/clusters/default/namespaces/{ns}/pods/{name}/exec?container=<c>&command=/bin/sh`
  (WebSocket; binary stdin / combined stdout, JSON control frames for terminal resize).
- Session UI uses xterm.js, remembers theme, supports container picker on
  multi-container pods and shell picker (`/bin/sh`, `/bin/bash`, `/bin/ash`).
- Idle timeout: **5 minutes** without stdin automatically closes the session.
- Each session logs `pod.exec.start` and `pod.exec.end` (with duration and
  outcome) to both the audit DB and the structured console log.
- ClusterRole must grant `pods/exec: create` for this to work.

Security notes:
- Exec is the highest-risk action in OpenConsole; grant it narrowly.
- Non-root pod admission policies in your cluster still apply.
- Session recording of stdout is deferred to a later milestone; command events
  (start/end) are already captured.

# Deployment Write Actions (restart, scale)

OpenConsole can **restart** (rolling restart) and **scale** Deployments when the
caller has been granted the matching application-level permissions:

- `deployments:restart` → `POST /api/namespaces/{ns}/deployments/{name}/restart`
- `deployments:scale`   → `POST /api/namespaces/{ns}/deployments/{name}/scale`
  with body `{"replicas": <int>}`

Both actions are **off by default** on every role — admins opt in explicitly in
*Admin → Roles → Role Permissions*, per role and per namespace.

- Every call records an audit entry — success, denied, failed, and rate_limited
  outcomes are all captured.
- Per-user rate limit: 5 burst, 1 token every 6s. 429 with `Retry-After` when exceeded.
- Scale accepts replicas between 0 and `MAX_REPLICAS` (env, default 100).
- The ServiceAccount's ClusterRole must grant `apps.deployments: patch` and
  `apps.deployments/scale: get,update` (see the ClusterRole example above).

Request/audit correlation: every HTTP response carries `X-Request-Id`; the same
id appears in the structured request log, the deployment.action log, and the
audit entry.

# Security Notes

- Grant each verb (patch, update on scale, pods/exec, pods/log) only if the
  matching application permission is also handed to at least one role.
- OpenConsole's ServiceAccount should never be granted more than the actions
  the UI will expose; secrets access and port-forward are intentionally not
  used by the app.
- Token rotation is recommended (every 6–12 months)
- Do not store generated tokens in Git
- Prefer one ServiceAccount per cluster
- OpenConsole does not bypass Kubernetes RBAC; it operates strictly within the permissions granted to its ServiceAccount.


## Recommended Production Pattern

- One ServiceAccount per cluster
- One kubeconfig per cluster
- Store tokens securely
- Rotate periodically
- Avoid using personal user credentials

---

## First Login

On first startup a default admin is created:

- **username**: `admin`
- **password**: `admin`

You will be forced to change the password on first login.

## Usage

1. Log in as admin.
2. **Admin → Cluster**: upload kubeconfig or token, validate, apply.
3. **Admin → LDAP / Azure AD**: configure optional identity providers.
4. **Admin → Users/Groups/Roles**: define access.
5. **Admin → Audit Logs**: filter, search, export CSV.

## Example LDAP (Active Directory) Config

> Replace the values with your environment. The example below is anonymized.

- **host**: `10.10.20.15`
- **port**: `389`
- **skip verify**: `false`
- **bind dn**: `CN=svc-openconsole,OU=ServiceAccounts,OU=IT,DC=example,DC=corp`
- **bind password**: `********`
- **user base dn**: `OU=Engineering,OU=Users,DC=example,DC=corp`
- **user filter**: `(sAMAccountName=%s*)`

## Azure AD Login (Single-Tenant, Optional)

Azure AD is supported as an additional login method and can run in parallel with local/LDAP authentication.

### Behavior

- Azure AD login is configured from **Admin → Azure AD**.
- On first successful Azure AD login, the user is automatically created in the local database.
- RBAC still uses the same local model (**Users → Groups → Roles**).
- Logout is application-local only (does not sign out globally from Microsoft).

### Required Azure App Registration Settings

- **Tenant type**: Single tenant
- **Redirect URI**: `https://<your-domain>/api/auth/azure/callback`
- **Scopes used by app**: `openid profile email`

> After first login, assign groups/roles in **Admin → Users/Groups/Roles** to grant namespace/resource access.

## Tips & Gotchas

- **Cluster connection is UI-only**. No env vars or mounted kubeconfigs.
- **Namespace visibility is permission-based**; if a user sees nothing, check role permissions.
- If LDAP bind password is already configured, toggle **Update Bind Password** only when changing it.
- Audit log filters can combine user/action/namespace/date range.
- Pod logs stream via WebSocket; verify connectivity from the backend pod to the API server.

---

Kubernetes OpenConsole is designed as an internal visibility platform and is **not** a Kubernetes security boundary.