package auth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"k8s-dashboard/backend/internal/problem"
)

// Microsoft Graph directory search (Admin → Users → New user → Azure AD): the
// app registration reads users with its own identity (client credentials;
// Application permission User.Read.All with admin consent).

// GraphRoot is the Microsoft Graph host of the cloud an Entra sign-in host
// belongs to.
// shortcut: login.microsoftonline.us is shared by GCC High (graph.microsoft.us)
// and DoD (dod-graph.microsoft.us); DoD needs a Graph setting of its own when
// someone runs there.
func GraphRoot(authority string) string {
	switch host := strings.TrimSuffix(strings.TrimPrefix(strings.ToLower(authority), "https://"), "/"); host {
	case "login.microsoftonline.us":
		return "https://graph.microsoft.us"
	case "login.chinacloudapi.cn", "login.partner.microsoftonline.cn":
		return "https://microsoftgraph.chinacloudapi.cn"
	default:
		return "https://graph.microsoft.com"
	}
}

// GraphUser is a person in Entra ID. Username is the OpenConsole account name:
// the UPN, or the mail of a guest (whose UPN carries #EXT#).
type GraphUser struct {
	ID          string `json:"id"`
	DisplayName string `json:"displayName"`
	Mail        string `json:"mail"`
	UPN         string `json:"userPrincipalName"`
	Username    string `json:"username"`
}

// GraphError says why Graph could not be used; Code is the API's reason code.
type GraphError struct {
	Code   string
	Detail string
}

func (e *GraphError) Error() string { return e.Code + ": " + e.Detail }

const (
	GraphForbidden     = problem.GraphForbidden
	GraphInvalidClient = problem.GraphInvalidClient
	GraphUnreachable   = problem.GraphUnreachable
)

// GraphClient reads Entra ID users for one app registration.
type GraphClient struct {
	Cfg       AzureADConfig
	GraphRoot string // e.g. https://graph.microsoft.com
	HTTP      *http.Client
	tok       string // one token for the client's calls (a search, an import)
}

func (g GraphClient) client() *http.Client {
	if g.HTTP != nil {
		return g.HTTP
	}
	return &http.Client{Timeout: 15 * time.Second}
}

func (g *GraphClient) token(ctx context.Context) (string, error) {
	if g.tok != "" {
		return g.tok, nil
	}
	form := url.Values{
		"grant_type":    {"client_credentials"},
		"client_id":     {g.Cfg.ClientID},
		"client_secret": {g.Cfg.ClientSecret},
		"scope":         {strings.TrimRight(g.GraphRoot, "/") + "/.default"},
	}
	endpoint := g.Cfg.authority() + "/" + url.PathEscape(g.Cfg.TenantID) + "/oauth2/v2.0/token"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return "", &GraphError{GraphUnreachable, err.Error()}
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := g.client().Do(req)
	if err != nil {
		return "", &GraphError{GraphUnreachable, err.Error()}
	}
	defer resp.Body.Close()
	var out struct {
		AccessToken string `json:"access_token"`
		Error       string `json:"error"`
		Description string `json:"error_description"`
	}
	_ = json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&out)
	if out.AccessToken != "" {
		g.tok = out.AccessToken
		return g.tok, nil
	}
	// 4xx with an OAuth error = Entra refused the app's credentials (invalid_client,
	// unauthorized_client, an unknown tenant); anything else is Entra not answering.
	if resp.StatusCode >= 400 && resp.StatusCode < 500 && out.Error != "" {
		return "", &GraphError{GraphInvalidClient, firstLine(out.Error + ": " + out.Description)}
	}
	return "", &GraphError{GraphUnreachable, "token endpoint: " + resp.Status}
}

// get calls Graph and decodes the JSON answer into v.
func (g *GraphClient) get(ctx context.Context, path string, query url.Values, v any) error {
	tok, err := g.token(ctx)
	if err != nil {
		return err
	}
	u := strings.TrimRight(g.GraphRoot, "/") + "/v1.0" + path
	if len(query) > 0 {
		u += "?" + query.Encode()
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return &GraphError{GraphUnreachable, err.Error()}
	}
	req.Header.Set("Authorization", "Bearer "+tok)
	req.Header.Set("ConsistencyLevel", "eventual") // required by $search
	resp, err := g.client().Do(req)
	if err != nil {
		return &GraphError{GraphUnreachable, err.Error()}
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if resp.StatusCode/100 == 2 {
		if err := json.Unmarshal(body, v); err != nil {
			return &GraphError{GraphUnreachable, "unreadable answer"}
		}
		return nil
	}
	var e struct {
		Error struct {
			Code    string `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	_ = json.Unmarshal(body, &e)
	detail := firstLine(strings.TrimPrefix(e.Error.Code+": "+e.Error.Message, ": "))
	if detail == "" {
		detail = resp.Status
	}
	switch resp.StatusCode {
	case http.StatusUnauthorized, http.StatusForbidden:
		return &GraphError{GraphForbidden, detail}
	case http.StatusNotFound:
		return &GraphError{problem.NotFound, detail}
	}
	return &GraphError{GraphUnreachable, detail}
}

const graphSelect = "id,displayName,mail,userPrincipalName"

// SearchUsers finds up to 25 people whose name, e-mail or UPN matches q.
func (g *GraphClient) SearchUsers(ctx context.Context, q string) ([]GraphUser, error) {
	// $search clauses are quoted; a quote or backslash in q would end one early.
	q = strings.NewReplacer(`"`, "", `\`, "").Replace(strings.TrimSpace(q))
	var out struct {
		Value []GraphUser `json:"value"`
	}
	query := url.Values{"$select": {graphSelect}, "$top": {"25"}}
	if q != "" {
		query.Set("$search", fmt.Sprintf(`"displayName:%s" OR "mail:%s" OR "userPrincipalName:%s"`, q, q, q))
	}
	if err := g.get(ctx, "/users", query, &out); err != nil {
		return nil, err
	}
	for i := range out.Value {
		out.Value[i].Username = graphUsername(out.Value[i])
	}
	return out.Value, nil
}

// User reads one person by object id (oid).
func (g *GraphClient) User(ctx context.Context, id string) (GraphUser, error) {
	var u GraphUser
	if err := g.get(ctx, "/users/"+url.PathEscape(id), url.Values{"$select": {graphSelect}}, &u); err != nil {
		return u, err
	}
	u.Username = graphUsername(u)
	return u, nil
}

// Test checks the app can read users (one row).
func (g *GraphClient) Test(ctx context.Context) error {
	var out struct {
		Value []GraphUser `json:"value"`
	}
	return g.get(ctx, "/users", url.Values{"$select": {"id"}, "$top": {"1"}}, &out)
}

// graphUsername: the UPN, or for a guest (UPN with #EXT#) the e-mail address.
func graphUsername(u GraphUser) string {
	if strings.Contains(strings.ToUpper(u.UPN), "#EXT#") {
		return strings.TrimSpace(u.Mail)
	}
	return strings.TrimSpace(u.UPN)
}

func firstLine(s string) string {
	s, _, _ = strings.Cut(strings.TrimSpace(s), "\n")
	s, _, _ = strings.Cut(s, "\r")
	if r := []rune(s); len(r) > 300 {
		s = string(r[:300]) + "…"
	}
	return s
}

// AsGraphError unwraps a GraphError (nil if err is another error).
func AsGraphError(err error) *GraphError {
	var ge *GraphError
	if errors.As(err, &ge) {
		return ge
	}
	return nil
}
