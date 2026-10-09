package ldapfake

// Shared fixture: a service account plus two users whose names share a
// prefix ("john" is listed first, so a prefix search for "jo" hits him
// before "jo").
const (
	BaseDN     = "DC=example,DC=corp"
	UsersDN    = "OU=Users,DC=example,DC=corp"
	ServiceDN  = "CN=svc-openconsole,OU=Service,DC=example,DC=corp"
	ServicePwd = "svc-pass"
	JohnPwd    = "john-pass"
	JoPwd      = "jo-pass"
)

// Directory returns the fixture entries.
func Directory() []Entry {
	return []Entry{
		{DN: ServiceDN, Password: ServicePwd, Attrs: map[string][]string{"cn": {"svc-openconsole"}}},
		{DN: "CN=John Smith," + UsersDN, Password: JohnPwd, Attrs: map[string][]string{
			"cn": {"John Smith"}, "sAMAccountName": {"john"}, "objectClass": {"user"},
		}},
		{DN: "CN=Jo Brown," + UsersDN, Password: JoPwd, Attrs: map[string][]string{
			"cn": {"Jo Brown"}, "sAMAccountName": {"jo"}, "objectClass": {"user"},
		}},
	}
}
