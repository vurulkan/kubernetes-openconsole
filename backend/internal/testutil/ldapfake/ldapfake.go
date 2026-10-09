// Package ldapfake runs an in-process LDAP server with a tiny in-memory
// directory, for tests of the LDAP sign-in, search and import flows. It
// supports simple bind, whole-subtree search under a base DN, and filters
// built from &, |, equality and leading / trailing * wildcards — enough for
// the filters OpenConsole is configured with. Test-only: never imported by
// the server binary.
package ldapfake

import (
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/jimlambrt/gldap"
)

// Entry is one directory object; Password is checked on bind.
type Entry struct {
	DN       string
	Password string
	Attrs    map[string][]string
}

// Server is a running fake directory.
type Server struct {
	Addr    string // host:port
	entries []Entry
	srv     *gldap.Server
}

// Start launches the server on a free localhost port; it stops when the test
// ends.
func Start(t *testing.T, entries []Entry) *Server {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := l.Addr().String()
	_ = l.Close()

	s := &Server{Addr: addr, entries: entries}
	srv, err := gldap.NewServer()
	if err != nil {
		t.Fatal(err)
	}
	mux, err := gldap.NewMux()
	if err != nil {
		t.Fatal(err)
	}
	if err := mux.Bind(s.bind); err != nil {
		t.Fatal(err)
	}
	if err := mux.Search(s.search); err != nil {
		t.Fatal(err)
	}
	if err := srv.Router(mux); err != nil {
		t.Fatal(err)
	}
	s.srv = srv
	go func() { _ = srv.Run(addr) }()
	t.Cleanup(func() { _ = srv.Stop() })

	deadline := time.Now().Add(5 * time.Second)
	for !srv.Ready() {
		if time.Now().After(deadline) {
			t.Fatal("fake LDAP server did not start")
		}
		time.Sleep(10 * time.Millisecond)
	}
	return s
}

// URL is the ldap:// URL of the server.
func (s *Server) URL() string { return "ldap://" + s.Addr }

func (s *Server) bind(w *gldap.ResponseWriter, r *gldap.Request) {
	resp := r.NewBindResponse(gldap.WithResponseCode(gldap.ResultInvalidCredentials))
	defer func() { _ = w.Write(resp) }()
	m, err := r.GetSimpleBindMessage()
	if err != nil {
		return
	}
	for _, e := range s.entries {
		if strings.EqualFold(e.DN, m.UserName) && e.Password == string(m.Password) {
			resp.SetResultCode(gldap.ResultSuccess)
			return
		}
	}
}

func (s *Server) search(w *gldap.ResponseWriter, r *gldap.Request) {
	done := r.NewSearchDoneResponse(gldap.WithResponseCode(gldap.ResultSuccess))
	defer func() { _ = w.Write(done) }()
	m, err := r.GetSearchMessage()
	if err != nil {
		done.SetResultCode(gldap.ResultOperationsError)
		return
	}
	match, err := compile(m.Filter)
	if err != nil {
		done.SetResultCode(gldap.ResultOperationsError)
		return
	}
	base := strings.ToLower(m.BaseDN)
	sent := 0
	for _, e := range s.entries {
		if !strings.HasSuffix(strings.ToLower(e.DN), base) || !match(e) {
			continue
		}
		if m.SizeLimit > 0 && int64(sent) >= m.SizeLimit {
			break
		}
		_ = w.Write(r.NewSearchResponseEntry(e.DN, gldap.WithAttributes(e.Attrs)))
		sent++
	}
}

// compile turns an LDAP filter string into a matcher.
func compile(filter string) (func(Entry) bool, error) {
	f, rest, err := parse(strings.TrimSpace(filter))
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(rest) != "" {
		return nil, fmt.Errorf("trailing filter text %q", rest)
	}
	return f, nil
}

func parse(s string) (func(Entry) bool, string, error) {
	if !strings.HasPrefix(s, "(") {
		return nil, "", fmt.Errorf("expected ( in %q", s)
	}
	s = s[1:]
	switch {
	case strings.HasPrefix(s, "&"), strings.HasPrefix(s, "|"):
		and := s[0] == '&'
		s = s[1:]
		var parts []func(Entry) bool
		for strings.HasPrefix(s, "(") {
			f, rest, err := parse(s)
			if err != nil {
				return nil, "", err
			}
			parts = append(parts, f)
			s = rest
		}
		if !strings.HasPrefix(s, ")") {
			return nil, "", fmt.Errorf("unclosed group")
		}
		return func(e Entry) bool {
			for _, p := range parts {
				if p(e) != and {
					return !and
				}
			}
			return and
		}, s[1:], nil
	default:
		end := strings.Index(s, ")")
		if end < 0 {
			return nil, "", fmt.Errorf("unclosed item")
		}
		item := s[:end]
		eq := strings.Index(item, "=")
		if eq < 0 {
			return nil, "", fmt.Errorf("bad item %q", item)
		}
		attr, pattern := strings.ToLower(item[:eq]), unescape(item[eq+1:])
		return func(e Entry) bool {
			for k, vals := range e.Attrs {
				if strings.ToLower(k) != attr {
					continue
				}
				for _, v := range vals {
					if wildcardMatch(strings.ToLower(pattern), strings.ToLower(v)) {
						return true
					}
				}
			}
			return false
		}, s[end+1:], nil
	}
}

// wildcardMatch supports * anywhere (prefix, suffix, presence).
func wildcardMatch(pattern, v string) bool {
	if pattern == "*" {
		return true
	}
	parts := strings.Split(pattern, "*")
	if len(parts) == 1 {
		return pattern == v
	}
	if !strings.HasPrefix(v, parts[0]) {
		return false
	}
	v = v[len(parts[0]):]
	for i := 1; i < len(parts)-1; i++ {
		idx := strings.Index(v, parts[i])
		if idx < 0 {
			return false
		}
		v = v[idx+len(parts[i]):]
	}
	return strings.HasSuffix(v, parts[len(parts)-1])
}

// unescape decodes \XX escapes produced by ldap.EscapeFilter.
func unescape(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+2 < len(s) {
			var c byte
			if _, err := fmt.Sscanf(s[i+1:i+3], "%02x", &c); err == nil {
				b.WriteByte(c)
				i += 2
				continue
			}
		}
		b.WriteByte(s[i])
	}
	return b.String()
}
