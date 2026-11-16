package auth

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	neturl "net/url"
	"strings"
	"time"

	"github.com/go-ldap/ldap/v3"
)

type LDAPConfig struct {
	Enabled           bool
	URL               string
	Host              string
	Port              int
	UseSSL            bool
	StartTLS          bool
	SkipVerify        bool
	CACert            string // PEM; empty = the system's CAs
	TimeoutSeconds    int
	BindDN            string
	BindPassword      string
	UserBaseDN        string
	UserBaseDNs       []string
	UserFilter        string
	UsernameAttribute string
}

func LDAPAuthenticate(cfg LDAPConfig, username, password string) error {
	_, err := LDAPAuthenticateUser(cfg, username, password)
	return err
}

// LDAPAuthenticateUser binds as the user and returns their name as the
// directory spells it (the username attribute), e.g. "john" for a typed
// "John". Falls back to the typed name when the entry has no such value.
func LDAPAuthenticateUser(cfg LDAPConfig, username, password string) (string, error) {
	if !cfg.Enabled {
		return "", fmt.Errorf("ldap disabled")
	}
	// An empty password would be an anonymous ("unauthenticated") bind,
	// which many directories accept for any DN.
	if password == "" {
		return "", fmt.Errorf("empty password")
	}
	conn, err := dialLDAP(cfg)
	if err != nil {
		return "", err
	}
	defer conn.Close()

	if cfg.BindDN != "" {
		if err := conn.Bind(cfg.BindDN, cfg.BindPassword); err != nil {
			return "", err
		}
	}

	userDN, canonical, err := findUser(conn, cfg, username)
	if err != nil {
		return "", err
	}
	if err := conn.Bind(userDN, password); err != nil {
		return "", err
	}
	if canonical == "" {
		canonical = username
	}
	return canonical, nil
}

type LDAPUser struct {
	Username string `json:"username"`
	DN       string `json:"dn"`
}

func SearchUsers(cfg LDAPConfig, query string) ([]LDAPUser, error) {
	if !cfg.Enabled {
		return nil, fmt.Errorf("ldap disabled")
	}
	conn, err := dialLDAP(cfg)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	if cfg.BindDN != "" {
		if err := conn.Bind(cfg.BindDN, cfg.BindPassword); err != nil {
			return nil, err
		}
	}

	baseDNs := cfg.UserBaseDNs
	if len(baseDNs) == 0 && cfg.UserBaseDN != "" {
		baseDNs = []string{cfg.UserBaseDN}
	}
	if len(baseDNs) == 0 {
		return nil, fmt.Errorf("user base DN not set")
	}

	filter := cfg.UserFilter
	if strings.Contains(filter, "%s") {
		filter = fmt.Sprintf(filter, ldap.EscapeFilter(query))
	}
	if filter == "" {
		filter = "(sAMAccountName=*)"
	}
	attribute := cfg.UsernameAttribute
	if attribute == "" {
		attribute = "sAMAccountName"
	}

	var users []LDAPUser
	for _, baseDN := range baseDNs {
		search := ldap.NewSearchRequest(
			baseDN,
			ldap.ScopeWholeSubtree,
			ldap.NeverDerefAliases,
			100,
			0,
			false,
			filter,
			[]string{"dn", attribute, "cn"},
			nil,
		)
		result, err := conn.Search(search)
		if err != nil {
			continue
		}
		for _, entry := range result.Entries {
			username := entry.GetAttributeValue(attribute)
			if username == "" {
				username = entry.GetAttributeValue("cn")
			}
			if username == "" {
				username = entry.DN
			}
			users = append(users, LDAPUser{Username: username, DN: entry.DN})
		}
	}
	return users, nil
}

func TestConnection(cfg LDAPConfig) error {
	if !cfg.Enabled {
		return fmt.Errorf("ldap disabled")
	}
	conn, err := dialLDAP(cfg)
	if err != nil {
		return err
	}
	defer conn.Close()
	if cfg.BindDN != "" {
		if err := conn.Bind(cfg.BindDN, cfg.BindPassword); err != nil {
			return err
		}
	}

	baseDNs := cfg.UserBaseDNs
	if len(baseDNs) == 0 && cfg.UserBaseDN != "" {
		baseDNs = []string{cfg.UserBaseDN}
	}
	if len(baseDNs) == 0 {
		return fmt.Errorf("user base DN not set")
	}

	for _, baseDN := range baseDNs {
		search := ldap.NewSearchRequest(
			baseDN,
			ldap.ScopeBaseObject,
			ldap.NeverDerefAliases,
			1,
			0,
			false,
			"(objectClass=*)",
			[]string{"dn"},
			nil,
		)
		if _, err := conn.Search(search); err != nil {
			return err
		}
	}
	return nil
}

// findUser returns the DN to bind as and the entry's username attribute.
func findUser(conn *ldap.Conn, cfg LDAPConfig, username string) (string, string, error) {
	baseDNs := cfg.UserBaseDNs
	if len(baseDNs) == 0 && cfg.UserBaseDN != "" {
		baseDNs = []string{cfg.UserBaseDN}
	}
	if len(baseDNs) == 0 {
		return "", "", fmt.Errorf("user base DN not set")
	}
	attr := cfg.UsernameAttribute
	if attr == "" {
		attr = "sAMAccountName"
	}
	filter := loginFilter(cfg, username)
	for _, baseDN := range baseDNs {
		search := ldap.NewSearchRequest(
			baseDN,
			ldap.ScopeWholeSubtree,
			ldap.NeverDerefAliases,
			1,
			0,
			false,
			filter,
			[]string{"dn", attr},
			nil,
		)
		result, err := conn.Search(search)
		if err != nil {
			continue
		}
		if len(result.Entries) > 0 {
			return result.Entries[0].DN, result.Entries[0].GetAttributeValue(attr), nil
		}
	}
	return "", "", fmt.Errorf("user not found")
}

// loginFilter builds the search filter that finds the DN to bind as. The
// configured user filter also drives the admin's search box, where a
// wildcard such as (sAMAccountName=%s*) is handy — but at login a prefix
// match could resolve "jo" to john's DN. When the placeholder sits next to a
// wildcard, the filter is ANDed with an exact match on the username
// attribute; filters without a wildcard are used unchanged.
func loginFilter(cfg LDAPConfig, username string) string {
	attr := cfg.UsernameAttribute
	if attr == "" {
		attr = "sAMAccountName"
	}
	exact := fmt.Sprintf("(%s=%s)", attr, ldap.EscapeFilter(username))
	filter := cfg.UserFilter
	if filter == "" {
		return exact
	}
	wildcard := strings.Contains(filter, "%s*") || strings.Contains(filter, "*%s")
	if strings.Contains(filter, "%s") {
		filter = fmt.Sprintf(filter, ldap.EscapeFilter(username))
	}
	if wildcard {
		return "(&" + filter + exact + ")"
	}
	return filter
}

// dialLDAP connects to the directory, TLS (ldaps or StartTLS) checked against
// the host name and the configured CA (else the system's), unless SkipVerify.
func dialLDAP(cfg LDAPConfig) (*ldap.Conn, error) {
	url := cfg.URL
	if url == "" {
		scheme := "ldap"
		if cfg.UseSSL {
			scheme = "ldaps"
		}
		port := cfg.Port
		if port == 0 {
			port = 389
		}
		url = fmt.Sprintf("%s://%s:%d", scheme, cfg.Host, port)
	}
	tlsCfg, err := ldapTLSConfig(cfg, url)
	if err != nil {
		return nil, err
	}
	timeout := time.Duration(cfg.TimeoutSeconds) * time.Second
	if timeout == 0 {
		timeout = 10 * time.Second
	}
	conn, err := ldap.DialURL(url, ldap.DialWithDialer(&net.Dialer{Timeout: timeout}), ldap.DialWithTLSConfig(tlsCfg))
	if err != nil {
		return nil, err
	}
	if cfg.StartTLS {
		if err := conn.StartTLS(tlsCfg); err != nil {
			conn.Close()
			return nil, err
		}
	}
	return conn, nil
}

func ldapTLSConfig(cfg LDAPConfig, rawURL string) (*tls.Config, error) {
	u, err := neturl.Parse(rawURL)
	if err != nil {
		return nil, fmt.Errorf("ldap url: %w", err)
	}
	tlsCfg := &tls.Config{ServerName: u.Hostname(), InsecureSkipVerify: cfg.SkipVerify, MinVersion: tls.VersionTLS12}
	if strings.TrimSpace(cfg.CACert) != "" {
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM([]byte(cfg.CACert)) {
			return nil, fmt.Errorf("ldap CA certificate: no PEM certificate found")
		}
		tlsCfg.RootCAs = pool
	}
	return tlsCfg, nil
}
