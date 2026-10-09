package auth

import "testing"

func TestLoginFilter(t *testing.T) {
	cases := []struct {
		filter, attr, user, want string
	}{
		// Wildcard search filter → exact match added for login.
		{"(sAMAccountName=%s*)", "", "jo", "(&(sAMAccountName=jo*)(sAMAccountName=jo))"},
		{"(&(objectClass=person)(uid=*%s*))", "uid", "jo", "(&(&(objectClass=person)(uid=*jo*))(uid=jo))"},
		// Exact filters are left alone.
		{"(sAMAccountName=%s)", "", "jo", "(sAMAccountName=jo)"},
		{"(&(objectClass=user)(mail=%s))", "mail", "a@b.c", "(&(objectClass=user)(mail=a@b.c))"},
		// No filter → exact match on the username attribute.
		{"", "uid", "jo", "(uid=jo)"},
		// Input is escaped.
		{"(uid=%s*)", "uid", "j*(", `(&(uid=j\2a\28*)(uid=j\2a\28))`},
	}
	for _, c := range cases {
		got := loginFilter(LDAPConfig{UserFilter: c.filter, UsernameAttribute: c.attr}, c.user)
		if got != c.want {
			t.Errorf("loginFilter(%q, %q) = %q, want %q", c.filter, c.user, got, c.want)
		}
	}
}
