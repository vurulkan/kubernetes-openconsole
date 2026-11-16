package api

import (
	"context"
	"encoding/json"
	"go/ast"
	"go/parser"
	"go/token"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"k8s-dashboard/backend/internal/problem"
)

// Every error answer names a registered reason code: writeError /
// writeErrorDetail / problem.Write get a constant (or a variable that carries
// one through), never free text. Free text is what the UI couldn't translate
// and agents couldn't switch on (M29).
func TestErrorCodesAreRegistered(t *testing.T) {
	fset := token.NewFileSet()
	raw := map[string]ast.Expr{} // const name → its value expression, across api, auth and problem
	var files []*ast.File
	for _, dir := range []string{".", "../auth", "../problem"} {
		paths, _ := filepath.Glob(filepath.Join(dir, "*.go"))
		for _, p := range paths {
			if strings.HasSuffix(p, "_test.go") {
				continue
			}
			f, err := parser.ParseFile(fset, p, nil, 0)
			if err != nil {
				t.Fatal(err)
			}
			files = append(files, f)
			for _, d := range f.Decls {
				g, ok := d.(*ast.GenDecl)
				if !ok || g.Tok != token.CONST {
					continue
				}
				for _, sp := range g.Specs {
					v := sp.(*ast.ValueSpec)
					for i, n := range v.Names {
						if i < len(v.Values) {
							raw[n.Name] = v.Values[i]
						}
					}
				}
			}
		}
	}
	consts := map[string]string{} // const name → string value
	var resolve func(e ast.Expr) (string, bool)
	resolve = func(e ast.Expr) (string, bool) {
		switch v := e.(type) {
		case *ast.BasicLit:
			s, err := strconv.Unquote(v.Value)
			return s, err == nil
		case *ast.Ident:
			if x, ok := raw[v.Name]; ok {
				return resolve(x)
			}
		case *ast.SelectorExpr:
			if x, ok := raw[v.Sel.Name]; ok {
				return resolve(x)
			}
		}
		return "", false
	}
	for name, x := range raw {
		if s, ok := resolve(x); ok {
			consts[name] = s
		}
	}
	// Variables that carry a code from a constant through (checked at their source).
	passThrough := map[string]bool{"reason": true, "code": true, "logsEvent.Reason": true, "podLogs.Reason": true,
		"kubeWriteCode()": true, "s.denyReason()": true}
	checked := 0
	for _, f := range files {
		ast.Inspect(f, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			name := exprString(call.Fun, nil)
			if name != "writeError" && name != "writeErrorDetail" && name != "problem.Write" && name != "Write" && name != "wsFail" && name != "refuse" {
				return true
			}
			idx := 2
			if name == "wsFail" {
				idx = 3
			}
			if len(call.Args) <= idx || (name == "Write" && f.Name.Name != "problem") {
				return true
			}
			arg := call.Args[idx]
			pos := fset.Position(arg.Pos())
			if lit, ok := arg.(*ast.BasicLit); ok && name == "wsFail" {
				_ = lit // wsFail's literal reasons are log-frame reasons; their HTTP answer maps them
				return true
			}
			src := exprString(arg, nil)
			if lit, ok := arg.(*ast.BasicLit); ok {
				t.Errorf("%s: %s gets the literal %s; use a problem constant", pos, name, lit.Value)
				return true
			}
			if passThrough[src] || f.Name.Name == "problem" {
				return true
			}
			val, ok := consts[strings.TrimPrefix(src, "problem.")]
			if !ok {
				t.Errorf("%s: %s gets %s, not a reason-code constant", pos, name, src)
				return true
			}
			if !problem.Known(val) {
				t.Errorf("%s: %q is not in problem.Codes", pos, val)
			}
			checked++
			return true
		})
	}
	if checked < 200 {
		t.Fatalf("only %d calls checked; is the scan still finding them?", checked)
	}
}

func exprString(e ast.Expr, consts map[string]string) string {
	switch v := e.(type) {
	case *ast.Ident:
		if consts != nil {
			if s, ok := consts[v.Name]; ok {
				return s
			}
		}
		return v.Name
	case *ast.SelectorExpr:
		if consts != nil {
			if s, ok := consts[v.Sel.Name]; ok {
				return s
			}
		}
		return exprString(v.X, nil) + "." + v.Sel.Name
	case *ast.BasicLit:
		s, _ := strconv.Unquote(v.Value)
		return s
	case *ast.CallExpr:
		return exprString(v.Fun, nil) + "()"
	}
	return "?"
}

func TestProblemCodesInOpenAPI(t *testing.T) {
	var doc struct {
		Components struct {
			Schemas struct {
				Problem struct {
					Properties struct {
						Error struct {
							Enum        []string `json:"enum"`
							Description string   `json:"description"`
						} `json:"error"`
					} `json:"properties"`
				} `json:"Problem"`
			} `json:"schemas"`
		} `json:"components"`
	}
	if err := json.Unmarshal(openapiJSON, &doc); err != nil {
		t.Fatal(err)
	}
	e := doc.Components.Schemas.Problem.Properties.Error
	var want []string
	for _, c := range problem.Codes {
		want = append(want, c.Code)
		if !strings.Contains(e.Description, "`"+c.Code+"`: "+c.Doc) {
			t.Errorf("openapi.yaml Problem.error description lacks %q", c.Code)
		}
	}
	if !slices.Equal(e.Enum, want) {
		t.Fatalf("openapi.yaml Problem.error enum = %v\nproblem.Codes      = %v", e.Enum, want)
	}
}

func decodeProblem(t *testing.T, body string) problem.Body {
	t.Helper()
	var p problem.Body
	if err := json.Unmarshal([]byte(body), &p); err != nil {
		t.Fatalf("not a problem body: %q", body)
	}
	return p
}

func (e *testEnv) raw(method, path, token string) (*http.Response, string) {
	e.t.Helper()
	req, _ := http.NewRequest(method, e.http.URL+path, nil)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		e.t.Fatal(err)
	}
	defer resp.Body.Close()
	var b strings.Builder
	buf := make([]byte, 4096)
	for {
		n, err := resp.Body.Read(buf)
		b.Write(buf[:n])
		if err != nil {
			break
		}
	}
	return resp, b.String()
}

func TestErrorBodyIsProblemDetails(t *testing.T) {
	e := newTestEnv(t)
	_, admin := e.user("root", true)
	resp, body := e.raw("GET", "/api/admin/users/abc/groups", admin)
	if resp.StatusCode != http.StatusBadRequest || resp.Header.Get("Content-Type") != "application/problem+json" {
		t.Fatalf("status %d, type %q", resp.StatusCode, resp.Header.Get("Content-Type"))
	}
	if p := decodeProblem(t, body); p != (problem.Body{Type: "about:blank", Title: "Bad Request", Status: 400, Error: problem.InvalidID}) {
		t.Fatalf("body = %+v", p)
	}
	// Free text became a code; the text moved to detail.
	code, body := e.do("POST", "/api/admin/users", admin, map[string]any{"username": "x", "password": "short", "source": "local"})
	if p := decodeProblem(t, body); code != http.StatusBadRequest || p.Error != problem.WeakPassword || p.Detail == "" {
		t.Fatalf("weak password: %d %+v", code, p)
	}
}

// An unknown /api or /ws path is a JSON 404, not the SPA's index.html with 200;
// a known path with the wrong method is 405 with Allow.
func TestUnknownAPIPathIsJSON(t *testing.T) {
	e := newTestEnv(t)
	static := filepath.Join(e.tmp, "public")
	if err := os.MkdirAll(static, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(static, "index.html"), []byte("<html>spa</html>"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, admin := e.user("root", true)
	for _, p := range []string{"/api/clusters", "/api", "/ws/nothing"} {
		resp, body := e.raw("GET", p, admin)
		if resp.StatusCode != http.StatusNotFound || decodeProblem(t, body).Error != problem.NotFound {
			t.Fatalf("GET %s = %d %q", p, resp.StatusCode, body)
		}
	}
	resp, body := e.raw("PATCH", "/api/admin/users", admin)
	if resp.StatusCode != http.StatusMethodNotAllowed || decodeProblem(t, body).Error != problem.MethodNotAllowed {
		t.Fatalf("PATCH /api/admin/users = %d %q", resp.StatusCode, body)
	}
	if allow := resp.Header.Values("Allow"); !slices.Contains(allow, "GET") || !slices.Contains(allow, "POST") {
		t.Fatalf("Allow = %v", allow)
	}
	// The SPA still owns every other path.
	if resp, body := e.raw("GET", "/admin/users", ""); resp.StatusCode != http.StatusOK || !strings.Contains(body, "spa") {
		t.Fatalf("GET /admin/users = %d %q", resp.StatusCode, body)
	}
}

// What an agent sees when its key is refused: a reason, and when to retry.
func TestAPIKeyRefusalReasons(t *testing.T) {
	e := newTestEnv(t)
	bobID, bob := e.user("bob", false)
	e.grant(bobID, [4]any{0, "team-a", "pods", "list"})
	check := func(token string, status int, code string) http.Header {
		t.Helper()
		resp, body := e.raw("GET", "/api/namespaces/team-a/pods", token)
		if resp.StatusCode != status || decodeProblem(t, body).Error != code {
			t.Fatalf("got %d %q, want %d %s", resp.StatusCode, body, status, code)
		}
		return resp.Header
	}
	check("", http.StatusUnauthorized, problem.Unauthorized)
	check("oc_unknownunknownunknown", http.StatusUnauthorized, problem.Unauthorized)

	revoked, id := e.createKey(bob, keyBody("revoked", []string{"team-a"}, "pods:list"))
	e.expect("POST", "/api/me/api-keys/"+itoa(int64(id))+"/revoke", bob, nil, http.StatusOK)
	check(revoked, http.StatusUnauthorized, problem.APIKeyRevoked)

	expired, expiredID := e.createKey(bob, keyBody("expired", []string{"team-a"}, "pods:list"))
	past := time.Now().Add(-time.Minute)
	if err := e.store.RegenerateAPIKey(context.Background(), expiredID, expired[:9], hashAPIKey(expired), &past); err != nil {
		t.Fatal(err)
	}
	check(expired, http.StatusUnauthorized, problem.APIKeyExpired)

	key, _ := e.createKey(bob, keyBody("busy", []string{"team-a"}, "pods:list"))
	for i := 0; i < apiKeyBurst+10; i++ {
		resp, body := e.raw("GET", "/api/features", key)
		if resp.StatusCode == http.StatusTooManyRequests {
			if decodeProblem(t, body).Error != problem.RateLimited || resp.Header.Get("Retry-After") != "1" {
				t.Fatalf("429: %q, Retry-After %q", body, resp.Header.Get("Retry-After"))
			}
			return
		}
	}
	t.Fatal("never rate limited")
}

func TestKubeWriteCodeIsRegistered(t *testing.T) {
	for st := 400; st < 600; st++ {
		if c := kubeWriteCode(st); !problem.Known(c) {
			t.Fatalf("kubeWriteCode(%d) = %q", st, c)
		}
	}
}

// The UI turns every reason code into a sentence (frontend/src/services/api.ts
// ERROR_CODES, with EN / TR text checked by api.test.ts): a code the UI doesn't
// know would show as a bare code.
func TestUIKnowsEveryErrorCode(t *testing.T) {
	src, err := os.ReadFile("../../../frontend/src/services/api.ts")
	if err != nil {
		t.Skip("no frontend checkout:", err)
	}
	s := string(src)
	i := strings.Index(s, "export const ERROR_CODES = [")
	j := strings.Index(s[i:], "];")
	if i < 0 || j < 0 {
		t.Fatal("ERROR_CODES not found in api.ts")
	}
	var ui []string
	for _, line := range strings.Split(s[i:i+j], "\n")[1:] {
		if v := strings.Trim(strings.TrimSpace(line), "',"); v != "" {
			ui = append(ui, v)
		}
	}
	var want []string
	for _, c := range problem.Codes {
		want = append(want, c.Code)
	}
	slices.Sort(ui)
	slices.Sort(want)
	if !slices.Equal(ui, want) {
		t.Fatalf("api.ts ERROR_CODES = %v\nproblem.Codes       = %v", ui, want)
	}
}
