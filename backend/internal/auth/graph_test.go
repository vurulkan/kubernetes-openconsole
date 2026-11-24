package auth

import "testing"

func TestGraphRoot(t *testing.T) {
	for authority, want := range map[string]string{
		"":                                  "https://graph.microsoft.com",
		"https://login.microsoftonline.com": "https://graph.microsoft.com",
		"https://login.microsoftonline.us/": "https://graph.microsoft.us",
		"https://login.chinacloudapi.cn":    "https://microsoftgraph.chinacloudapi.cn",
		"https://login.partner.microsoftonline.cn": "https://microsoftgraph.chinacloudapi.cn",
	} {
		if got := GraphRoot(authority); got != want {
			t.Errorf("GraphRoot(%q) = %q, want %q", authority, got, want)
		}
	}
	if got := graphUsername(GraphUser{UPN: "a_b.com#EXT#@t.onmicrosoft.com", Mail: "a@b.com"}); got != "a@b.com" {
		t.Errorf("guest username = %q", got)
	}
	if got := graphUsername(GraphUser{UPN: "jane@corp.com", Mail: "j@corp.com"}); got != "jane@corp.com" {
		t.Errorf("member username = %q", got)
	}
}
