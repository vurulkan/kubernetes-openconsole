package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"

	"k8s-dashboard/backend/internal/api"
	"k8s-dashboard/backend/internal/config"
	"k8s-dashboard/backend/internal/rbac"
)

// ── Environment variables ────────────────────────────────────────────────────

var sectionIntro = map[string]string{
	"Core": "A value that doesn't parse, or is below the minimum, falls back to the default.",
	"Session recording": "Recording is configured in **Admin → Recordings → Recording settings** and stored in the database. " +
		"These variables only seed those settings on the very first start (useful for scripted installs), except " +
		"`SESSION_RECORDING_DIR`, which is read on every start.",
}

func envPage(root string) (string, error) {
	image, err := dockerfileEnv(filepath.Join(root, "Dockerfile"))
	if err != nil {
		return "", err
	}
	manifest, err := deploymentEnv(filepath.Join(root, "deploy/deployment.yaml"))
	if err != nil {
		return "", err
	}
	var b strings.Builder
	b.WriteString("Every variable the server reads. Set them on the container; `deploy/deployment.yaml` lists the common ones. " +
		"**Default** is what the server uses when the variable is unset; the image and `deploy/deployment.yaml` set a few themselves.\n\n")
	for _, section := range config.Sections {
		fmt.Fprintf(&b, "## %s\n\n", section)
		if intro := sectionIntro[section]; intro != "" {
			b.WriteString(intro + "\n\n")
		}
		var rows [][]string
		for _, v := range config.Vars {
			if v.Section != section {
				continue
			}
			def := "none"
			if v.Default != "" {
				def = code(v.Default)
				if v.Default == "the build version" {
					def = v.Default
				}
			}
			if val, ok := image[v.Name]; ok {
				def += "; image: " + code(val)
			}
			if val, ok := manifest[v.Name]; ok && val != image[v.Name] && val != v.Default {
				def += "; `deployment.yaml`: " + code(val)
			}
			rows = append(rows, []string{code(v.Name), def, v.Description})
		}
		table(&b, []string{"Variable", "Default", "Description"}, rows)
	}
	b.WriteString("## Feature flags\n\n" +
		"Switch a capability off **for everyone, admins included**, whatever the roles grant: `FEATURE_<NAME>=false` " +
		"(or `0`, `no`). Anything else, or unset, leaves it on. A disabled feature disappears from the UI, its endpoints " +
		"answer 403 `feature_disabled` and the attempt is audited as `denied`. `GET /api/features` shows the current state; " +
		"the startup log lists what is off.\n\n")
	var rows [][]string
	for _, f := range api.AllFeatures {
		rows = append(rows, []string{code("FEATURE_" + strings.ToUpper(f)), api.FeatureDocs[f]})
	}
	table(&b, []string{"Variable", "`false` turns off"}, rows)
	return b.String(), nil
}

// dockerfileEnv reads the ENV lines of the final stage (KEY=VALUE form).
func dockerfileEnv(path string) (map[string]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	out := map[string]string{}
	inEnv := false
	pair := regexp.MustCompile(`([A-Z][A-Z0-9_]*)=(\S+)`)
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if strings.HasPrefix(line, "FROM ") {
			out = map[string]string{} // only the last stage counts
		}
		if strings.HasPrefix(line, "ENV ") || inEnv {
			for _, m := range pair.FindAllStringSubmatch(line, -1) {
				out[m[1]] = m[2]
			}
			inEnv = strings.HasSuffix(line, `\`)
		}
	}
	return out, sc.Err()
}

// deploymentEnv reads the container env of deploy/deployment.yaml.
func deploymentEnv(path string) (map[string]string, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var d struct {
		Spec struct {
			Template struct {
				Spec struct {
					Containers []struct {
						Env []struct{ Name, Value string }
					}
				}
			}
		}
	}
	if err := yaml.Unmarshal(raw, &d); err != nil {
		return nil, err
	}
	out := map[string]string{}
	for _, c := range d.Spec.Template.Spec.Containers {
		for _, e := range c.Env {
			if e.Value != "" {
				out[e.Name] = e.Value
			}
		}
	}
	return out, nil
}

// ── Application permissions ─────────────────────────────────────────────────

func permissionsPage(root string) (string, error) {
	endpoints, err := permissionEndpoints(filepath.Join(root, "backend/internal/api/openapi.yaml"))
	if err != nil {
		return "", err
	}
	var b strings.Builder
	b.WriteString("Granted per role, per namespace, per cluster (or all clusters) under **Admin → Roles**. Admins hold all of them. " +
		"A user's permission is checked on every request, in the namespace of the request.\n\n" +
		"**Safe read-only** marks the grants of the API access mode of the same name and of the API key template: " +
		"`list`, `get` and `logs`, except on ConfigMaps and Secrets, whose data can hold credentials.\n\n" +
		"**Endpoints** come from the API description (`/api/openapi.json`); an endpoint that needs two permissions is " +
		"listed under both. The Kubernetes rights behind each one are on [Kubernetes permissions](kubernetes-permissions.md).\n\n")
	for _, c := range rbac.Catalog {
		fmt.Fprintf(&b, "## %s\n\n", rbac.ResourceDocs[c.Resource])
		var rows [][]string
		for _, a := range c.Actions {
			safe := ""
			if rbac.SafeRead(c.Resource, a) {
				safe = "yes"
			}
			eps := endpoints[c.Resource+":"+a]
			eps = append(eps, endpoints["*:"+a]...)
			rows = append(rows, []string{code(c.Resource + ":" + a), rbac.ActionDoc(c.Resource, a), safe, strings.Join(eps, "<br/>")})
		}
		table(&b, []string{"Permission", "Opens", "Safe read-only", "Endpoints"}, rows)
	}
	return b.String(), nil
}

// openAPI is the part of openapi.yaml docgen reads.
type openAPI struct {
	Paths map[string]map[string]yaml.Node `yaml:"paths"` // method → operation, plus "parameters"
}

type operation struct {
	Permission []string `yaml:"x-openconsole-permission"`
}

var httpMethods = []string{"get", "post", "put", "patch", "delete"}

// permissionEndpoints maps "resource:action" to the endpoints that need it.
func permissionEndpoints(path string) (map[string][]string, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var spec openAPI
	if err := yaml.Unmarshal(raw, &spec); err != nil {
		return nil, err
	}
	out := map[string][]string{}
	for _, p := range sortedKeys(spec.Paths) {
		for _, m := range httpMethods {
			node, ok := spec.Paths[p][m]
			if !ok {
				continue
			}
			var op operation
			if err := node.Decode(&op); err != nil {
				return nil, fmt.Errorf("%s %s: %w", m, p, err)
			}
			for _, perm := range op.Permission {
				label := code(strings.ToUpper(m) + " " + p)
				if len(op.Permission) > 1 {
					label += " (with " + codeList(without(op.Permission, perm)) + ")"
				}
				out[perm] = append(out[perm], label)
			}
		}
	}
	return out, nil
}

func without(list []string, s string) []string {
	var out []string
	for _, v := range list {
		if v != s {
			out = append(out, v)
		}
	}
	return out
}

// ── Metrics ─────────────────────────────────────────────────────────────────

func metricsPage(string) (string, error) {
	var b strings.Builder
	b.WriteString("`GET /metrics` serves these in the Prometheus text format, without sign-in: scrape it from inside the " +
		"cluster and don't route it through your Ingress. Counters start at 0 when the pod starts.\n\n")
	var rows [][]string
	for _, m := range api.Metrics {
		labels := ""
		if len(m.Labels) > 0 {
			labels = codeList(m.Labels)
		}
		rows = append(rows, []string{code(m.Name), m.Type, labels, m.Help})
	}
	table(&b, []string{"Metric", "Type", "Labels", "Meaning"}, rows)
	return b.String(), nil
}

// ── Kubernetes permissions ──────────────────────────────────────────────────

type rbacRule struct {
	APIGroups     []string `yaml:"apiGroups"`
	Resources     []string `yaml:"resources"`
	ResourceNames []string `yaml:"resourceNames"`
	Verbs         []string `yaml:"verbs"`
	about         string
	optional      bool // commented out in the file
}

func kubeRBACPage(root string) (string, error) {
	var b strings.Builder
	b.WriteString("OpenConsole talks to each cluster with the identity you give it under **Admin → Clusters**, normally the " +
		"ServiceAccount of `deploy/rbac.yaml`. That ClusterRole is the ceiling: a user can never do more in a cluster than " +
		"it allows, whatever their OpenConsole roles grant. Remove a rule if you will never grant the matching permission. " +
		"For a console that can only look, apply `deploy/rbac-readonly.yaml` instead (same object names, so applying one " +
		"replaces the other).\n\n")
	for _, f := range []struct{ file, title string }{
		{"deploy/rbac.yaml", "Full (`deploy/rbac.yaml`)"},
		{"deploy/rbac-readonly.yaml", "Read only (`deploy/rbac-readonly.yaml`)"},
	} {
		rules, err := clusterRoleRules(filepath.Join(root, f.file))
		if err != nil {
			return "", fmt.Errorf("%s: %w", f.file, err)
		}
		fmt.Fprintf(&b, "## %s\n\n", f.title)
		var rows [][]string
		for _, r := range rules {
			groups := make([]string, len(r.APIGroups))
			for i, g := range r.APIGroups {
				if g == "" {
					g = "core"
				}
				groups[i] = g
			}
			res := codeList(r.Resources)
			if len(r.ResourceNames) > 0 {
				res += " (only " + codeList(r.ResourceNames) + ")"
			}
			about := r.about
			if r.optional {
				about = "**Not granted** (commented out in the file). " + about
			}
			rows = append(rows, []string{strings.Join(groups, ", "), res, codeList(r.Verbs), about})
		}
		table(&b, []string{"API group", "Resources", "Verbs", "Used for"}, rows)
	}
	return b.String(), nil
}

var ruleStart = regexp.MustCompile(`^  - apiGroups:`)

// clusterRoleRules reads the rules of the ClusterRole in path with the comment
// paragraph above each one. A rule that is commented out ("# - apiGroups:")
// is returned as optional.
func clusterRoleRules(path string) ([]rbacRule, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	lines := strings.Split(string(raw), "\n")
	start := -1
	for i, l := range lines {
		if l == "kind: ClusterRole" {
			start = i
		}
		if start >= 0 && i > start && l == "rules:" {
			start = i + 1
			break
		}
	}
	if start < 0 {
		return nil, fmt.Errorf("no ClusterRole rules")
	}
	var rules []rbacRule
	var prose, code []string // the current comment paragraph
	flushCode := func() error {
		if len(code) == 0 {
			return nil
		}
		r, err := parseRule(code)
		if err != nil {
			return err
		}
		r.about, r.optional = strings.Join(prose, " "), true
		rules = append(rules, r)
		prose, code = nil, nil
		return nil
	}
	for i := start; i < len(lines) && lines[i] != "---"; i++ {
		l := lines[i]
		trimmed := strings.TrimSpace(l)
		switch {
		case trimmed == "":
			if err := flushCode(); err != nil {
				return nil, err
			}
			prose = nil
		case strings.HasPrefix(trimmed, "#"):
			text := strings.TrimPrefix(strings.TrimPrefix(trimmed, "#"), " ")
			if strings.HasPrefix(text, "- ") || strings.HasPrefix(text, "  ") {
				code = append(code, "  "+text)
			} else {
				prose = append(prose, text)
			}
		case ruleStart.MatchString(l):
			if err := flushCode(); err != nil {
				return nil, err
			}
			block := []string{l}
			for i+1 < len(lines) && strings.HasPrefix(lines[i+1], "    ") {
				i++
				block = append(block, lines[i])
			}
			r, err := parseRule(block)
			if err != nil {
				return nil, err
			}
			if len(prose) == 0 {
				return nil, fmt.Errorf("rule %q has no comment above it saying what it is for", strings.TrimSpace(block[1]))
			}
			r.about = strings.Join(prose, " ")
			rules = append(rules, r)
			prose = nil
		}
	}
	return rules, flushCode()
}

func parseRule(block []string) (rbacRule, error) {
	var rs []rbacRule
	src := strings.Join(block, "\n")
	// Drop trailing "# …" comments inside the commented-out rule.
	src = regexp.MustCompile(`\s+#.*`).ReplaceAllString(src, "")
	if err := yaml.Unmarshal([]byte(src), &rs); err != nil || len(rs) != 1 {
		return rbacRule{}, fmt.Errorf("can't read rule %q: %v", src, err)
	}
	return rs[0], nil
}

// ── Keyboard shortcuts ──────────────────────────────────────────────────────

type shortcutGroup struct {
	ID    string            `json:"id"`
	Title map[string]string `json:"title"`
	Rows  []struct {
		Keys []string          `json:"keys"`
		Join string            `json:"join"`
		Text map[string]string `json:"text"`
	} `json:"rows"`
}

func shortcutsPage(root string) (string, error) {
	raw, err := os.ReadFile(filepath.Join(root, "frontend/src/shortcuts.json"))
	if err != nil {
		return "", err
	}
	var groups []shortcutGroup
	if err := json.Unmarshal(raw, &groups); err != nil {
		return "", err
	}
	var b strings.Builder
	b.WriteString("The same list as **?** in the app. \"`g` then `o`\" means: press `g`, then `o` within a second; \"or\" " +
		"means either key works. On a Turkish Q keyboard the shortcuts follow the key's position, so `ğ` `ü` `.` work as " +
		"`[` `]` `/`. Shortcuts don't fire while you type in a text field.\n\n")
	for _, g := range groups {
		fmt.Fprintf(&b, "## %s\n\n", g.Title["en"])
		var rows [][]string
		for _, r := range g.Rows {
			sep := " then "
			if r.Join == "or" {
				sep = " or "
			}
			keys := make([]string, len(r.Keys))
			for i, k := range r.Keys {
				keys[i] = "<kbd>" + k + "</kbd>"
			}
			rows = append(rows, []string{strings.Join(keys, sep), r.Text["en"]})
		}
		table(&b, []string{"Keys", "Does"}, rows)
	}
	return b.String(), nil
}
