# Kubernetes OpenConsole

Modern, production-ready Kubernetes visibility dashboard with strict application-level authorization. Runs inside Kubernetes, reads cluster data with a single high-privilege identity, and enforces access strictly in the app layer (no Kubernetes RBAC for end users).

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

- **Backend**: Go + `client-go`
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
