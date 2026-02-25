# Kubernetes OpenConsole

Modern, production-ready Kubernetes visibility dashboard with strict application-level authorization. Runs inside Kubernetes, reads cluster data using a single ServiceAccount identity per cluster, and enforces access strictly in the app layer (no Kubernetes RBAC for end users).

## Highlights

- **Read-only Kubernetes visibility** (Pods, Deployments, Services, ConfigMaps)
- **Application-level RBAC**: user → groups → roles → per-namespace permissions
- **Namespace discovery is permission-based** (no leakage)
- **JWT authentication** with forced password change on first login
- **Local users** (bcrypt) + **LDAP auth** (bind-based) configurable via UI
- **Audit logs** with pagination, filters, and CSV export
- **WebSocket pod log streaming** with rate limiting
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

- `LOG_RETENTION_DAYS` (default: 30)  
  Audit log retention in days (purged automatically). Set directly in `deploy/deployment.yaml`.
- `TIMEZONE` (default: UTC)  
  Used for audit log timestamps.
- `DATA_PATH` (default: `/data/app.db`)  
  SQLite DB location.
- `STATIC_DIR` (default: `/app/public`)  
  Served React build output.

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
> - Assign a minimal read-only ClusterRole
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

  - apiGroups: ["apps"]
    resources:
      - deployments
    verbs: ["get", "list", "watch"]

  - apiGroups: ["networking.k8s.io"]
    resources:
      - ingresses
    verbs: ["get", "list", "watch"]

  - apiGroups: ["batch"]
    resources:
      - cronjobs
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
    server: https://YOUR_API_SERVER
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

# Security Notes

- This ServiceAccount is **read-only**
- It cannot:
  - exec into pods
  - port-forward
  - read secrets
  - modify resources
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
3. **Admin → Users/Groups/Roles**: define access.
4. **Admin → Audit Logs**: filter, search, export CSV.

## Example LDAP (Active Directory) Config

> Replace the values with your environment. The example below is anonymized.

- **host**: `10.10.20.15`
- **port**: `389`
- **skip verify**: `false`
- **bind dn**: `CN=svc-openconsole,OU=ServiceAccounts,OU=IT,DC=example,DC=corp`
- **bind password**: `********`
- **user base dn**: `OU=Engineering,OU=Users,DC=example,DC=corp`
- **user filter**: `(sAMAccountName=%s*)`

## Tips & Gotchas

- **Cluster connection is UI-only**. No env vars or mounted kubeconfigs.
- **Namespace visibility is permission-based**; if a user sees nothing, check role permissions.
- If LDAP bind password is already configured, toggle **Update Bind Password** only when changing it.
- Audit log filters can combine user/action/namespace/date range.
- Pod logs stream via WebSocket; verify connectivity from the backend pod to the API server.

---

Kubernetes OpenConsole is designed as an internal visibility platform and is **not** a Kubernetes security boundary.