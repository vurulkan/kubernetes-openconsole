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
}

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
