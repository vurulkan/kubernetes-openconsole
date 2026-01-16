package auth

import (
	"crypto/tls"
	"fmt"
	"net"
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
	TimeoutSeconds    int
	BindDN            string
	BindPassword      string
	UserBaseDN        string
	UserBaseDNs       []string
	UserFilter        string
	UsernameAttribute string
}

func LDAPAuthenticate(cfg LDAPConfig, username, password string) error {
	if !cfg.Enabled {
		return fmt.Errorf("ldap disabled")
	}
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
	timeout := time.Duration(cfg.TimeoutSeconds) * time.Second
	if timeout == 0 {
		timeout = 10 * time.Second
	}
	dialer := &net.Dialer{Timeout: timeout}
	conn, err := ldap.DialURL(url, ldap.DialWithDialer(dialer))
	if err != nil {
		return err
	}
	defer conn.Close()

	if cfg.StartTLS {
		if err := conn.StartTLS(&tls.Config{InsecureSkipVerify: cfg.SkipVerify}); err != nil {
			return err
		}
	}

	if cfg.BindDN != "" {
		if err := conn.Bind(cfg.BindDN, cfg.BindPassword); err != nil {
			return err
		}
	}

	userDN, err := findUserDN(conn, cfg, username)
	if err != nil {
		return err
	}
	if err := conn.Bind(userDN, password); err != nil {
		return err
	}
	return nil
}

type LDAPUser struct {
	Username string `json:"username"`
	DN       string `json:"dn"`
}

func SearchUsers(cfg LDAPConfig, query string) ([]LDAPUser, error) {
	if !cfg.Enabled {
		return nil, fmt.Errorf("ldap disabled")
	}
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
	timeout := time.Duration(cfg.TimeoutSeconds) * time.Second
	if timeout == 0 {
		timeout = 10 * time.Second
	}
	dialer := &net.Dialer{Timeout: timeout}
	conn, err := ldap.DialURL(url, ldap.DialWithDialer(dialer))
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	if cfg.StartTLS {
		if err := conn.StartTLS(&tls.Config{InsecureSkipVerify: cfg.SkipVerify}); err != nil {
			return nil, err
		}
	}
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
	timeout := time.Duration(cfg.TimeoutSeconds) * time.Second
	if timeout == 0 {
		timeout = 10 * time.Second
	}
	dialer := &net.Dialer{Timeout: timeout}
	conn, err := ldap.DialURL(url, ldap.DialWithDialer(dialer))
	if err != nil {
		return err
	}
	defer conn.Close()

	if cfg.StartTLS {
		if err := conn.StartTLS(&tls.Config{InsecureSkipVerify: cfg.SkipVerify}); err != nil {
			return err
		}
	}
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

func findUserDN(conn *ldap.Conn, cfg LDAPConfig, username string) (string, error) {
	baseDNs := cfg.UserBaseDNs
	if len(baseDNs) == 0 && cfg.UserBaseDN != "" {
		baseDNs = []string{cfg.UserBaseDN}
	}
	if len(baseDNs) == 0 {
		return "", fmt.Errorf("user base DN not set")
	}
	filter := cfg.UserFilter
	if strings.Contains(filter, "%s") {
		filter = fmt.Sprintf(filter, ldap.EscapeFilter(username))
	}
	if filter == "" {
		filter = fmt.Sprintf("(sAMAccountName=%s)", ldap.EscapeFilter(username))
	}
	for _, baseDN := range baseDNs {
		search := ldap.NewSearchRequest(
			baseDN,
			ldap.ScopeWholeSubtree,
			ldap.NeverDerefAliases,
			1,
			0,
			false,
			filter,
			[]string{"dn"},
			nil,
		)
		result, err := conn.Search(search)
		if err != nil {
			continue
		}
		if len(result.Entries) > 0 {
			return result.Entries[0].DN, nil
		}
	}
	return "", fmt.Errorf("user not found")
}
