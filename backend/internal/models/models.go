package models

import "time"

type User struct {
	ID                 int       `json:"id"`
	Username           string    `json:"username"`
	PasswordHash       string    `json:"-"`
	MustChangePassword bool      `json:"mustChangePassword"`
	IsActive           bool      `json:"isActive"`
	IsAdmin            bool      `json:"isAdmin"`
	CreatedAt          time.Time `json:"createdAt"`
	// AuthSource is where the user signs in: "local" (password stored here),
	// "ldap" or "azure". Only local users can have their password reset.
	AuthSource string `json:"authSource"`
	// ActiveClusterID is the cluster this user picked in the header
	// switcher; 0 = use the default cluster.
	ActiveClusterID int `json:"activeClusterId"`
}

// Where a user authenticates.
const (
	AuthSourceLocal = "local"
	AuthSourceLDAP  = "ldap"
	AuthSourceAzure = "azure"
)

type Group struct {
	ID   int    `json:"id"`
	Name string `json:"name"`
}

type Role struct {
	ID          int    `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description"`
}

// NamespacePermission grants a role one (cluster, namespace, resource, action)
// tuple. ClusterID == 0 means "all clusters" (wildcard) — this keeps every
// permission row written before multi-cluster phase 2 backwards compatible,
// since those rows have NULL in the DB and we treat NULL as 0.
type NamespacePermission struct {
	ID          int    `json:"id"`
	RoleID      int    `json:"roleId"`
	ClusterID   int    `json:"clusterId"`
	ClusterName string `json:"clusterName,omitempty"`
	Namespace   string `json:"namespace"`
	Resource    string `json:"resource"`
	Action      string `json:"action"`
}

type LDAPConfig struct {
	Enabled        bool     `json:"enabled"`
	URL            string   `json:"url"`
	Host           string   `json:"host"`
	Port           int      `json:"port"`
	UseSSL         bool     `json:"useSsl"`
	StartTLS       bool     `json:"startTls"`
	SkipVerify     bool     `json:"sslSkipVerify"`
	TimeoutSeconds int      `json:"timeoutSeconds"`
	BindDN         string   `json:"bindDn"`
	BindPassword   string   `json:"bindPassword"`
	UserBaseDN     string   `json:"userBaseDn"`
	UserBaseDNs    []string `json:"userBaseDns"`
	UserFilter     string   `json:"userFilter"`
	UsernameAttribute string `json:"usernameAttribute"`
	PasswordConfigured bool  `json:"passwordConfigured"`
}

type AzureADConfig struct {
	Enabled            bool   `json:"enabled"`
	TenantID           string `json:"tenantId"`
	ClientID           string `json:"clientId"`
	ClientSecret       string `json:"clientSecret"`
	RedirectURL        string `json:"redirectUrl"`
	PasswordConfigured bool   `json:"passwordConfigured"`
}

type SessionSettings struct {
	SessionMinutes int `json:"sessionMinutes"`
}

type KubeCredentials struct {
	Method     string `json:"method"`
	Kubeconfig []byte `json:"-"`
	Token      []byte `json:"-"`
	Server     string `json:"server"`
	CACert     []byte `json:"-"`
	Active     bool   `json:"active"`
}

type AuditLog struct {
	ID           int       `json:"id"`
	Timestamp    time.Time `json:"timestamp"`
	User         string    `json:"user"`
	Action       string    `json:"action"`
	Namespace    string    `json:"namespace"`
	ResourceType string    `json:"resourceType"`
	ResourceName string    `json:"resourceName"`
	// Cluster the action ran against ("" for cluster-independent actions
	// such as logins or admin settings).
	Cluster string `json:"cluster"`
}

// SessionTokenRow is one row from session_tokens with the owner's username
// joined in. RevokedAt is a pointer so JSON renders as null when the session
// is still live, and as the revocation timestamp once it is killed.
type SessionTokenRow struct {
	ID         int        `json:"id"`
	JTI        string     `json:"jti"`
	UserID     int        `json:"userId"`
	Username   string     `json:"username"`
	IssuedAt   time.Time  `json:"issuedAt"`
	LastUsedAt time.Time  `json:"lastUsedAt"`
	ExpiresAt  time.Time  `json:"expiresAt"`
	RevokedAt  *time.Time `json:"revokedAt,omitempty"`
	IP         string     `json:"ip"`
	UserAgent  string     `json:"userAgent"`
}

// SessionRecording is one pod-exec session captured as an asciicast v2 file.
// EndedAt is nil while the session is still open (or the process crashed
// mid-session and startup recovery has not closed the row yet).
type SessionRecording struct {
	ID         int        `json:"id"`
	SessionID  string     `json:"sessionId"`
	User       string     `json:"user"`
	Cluster    string     `json:"cluster"`
	Namespace  string     `json:"namespace"`
	Pod        string     `json:"pod"`
	Container  string     `json:"container"`
	StartedAt  time.Time  `json:"startedAt"`
	EndedAt    *time.Time `json:"endedAt,omitempty"`
	DurationMs int64      `json:"durationMs"`
	SizeBytes  int64      `json:"sizeBytes"`
	Truncated  bool       `json:"truncated"`
	RequestID  string     `json:"requestId"`
	Path       string     `json:"-"`
}

// RecordingFilter narrows ListRecordings. Empty strings / nil times are
// ignored; Limit <= 0 falls back to the store default.
type RecordingFilter struct {
	User      string
	Cluster   string
	Namespace string
	Pod       string
	From      *time.Time
	To        *time.Time
	Limit     int
	Offset    int
}

// Disk policies for when the recording quota or the free-space floor is hit.
const (
	RecordingPolicyEvictOldest = "evict_oldest"
	RecordingPolicyStop        = "stop"
)

// RecordingSettings is the admin-editable recording configuration. Env vars
// only seed the row on first boot; after that the DB copy wins.
type RecordingSettings struct {
	Enabled       bool   `json:"enabled"`
	RetentionDays int    `json:"retentionDays"` // 0 = never purge
	MaxSessionMB  int    `json:"maxSessionMb"`
	MaxTotalMB    int    `json:"maxTotalMb"`
	MinFreeMB     int    `json:"minFreeMb"`
	DiskPolicy    string `json:"diskPolicy"`
}
