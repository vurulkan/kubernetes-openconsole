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

type NamespacePermission struct {
	ID        int    `json:"id"`
	RoleID    int    `json:"roleId"`
	Namespace string `json:"namespace"`
	Resource  string `json:"resource"`
	Action    string `json:"action"`
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
