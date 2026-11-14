package main

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"k8s-dashboard/backend/internal/audit"
	"k8s-dashboard/backend/internal/logging"
)

func auditPage(root string) (string, error) {
	actions, err := scanAuditActions(filepath.Join(root, "backend/internal/audit"),
		filepath.Join(root, "backend/internal/api"), filepath.Join(root, "backend/internal/recording"))
	if err != nil {
		return "", err
	}
	var b strings.Builder
	b.WriteString("Every audited action is one event. It is stored in the database (**Admin → Audit Logs**, CSV export) and, " +
		"with `LOG_INCLUDE_AUDIT=true` (the default), written to stdout as one line, so the same fields can be filtered in " +
		"the UI and in your log platform. The **ECS** names apply with `LOG_FORMAT=ecs`; `json` uses the plain names.\n\n")

	b.WriteString("## Fields\n\n")
	var rows [][]string
	for _, f := range audit.FieldDocs {
		rows = append(rows, []string{code(f.Key), code(logging.ECSField(f.Key)), f.Description})
	}
	table(&b, []string{"Field", "ECS", "Meaning"}, rows)

	b.WriteString("## Actions\n\nThe action is `<resource type>.<verb>`. Read from the handlers' code; an action shows every " +
		"outcome it can end with. `<resource>` stands for any Kubernetes resource type the check is made for (`pod`, " +
		"`deployment`, …).\n\n")
	rows = nil
	for _, a := range sortedKeys(actions) {
		outs := sortedKeys(actions[a])
		sort.SliceStable(outs, func(i, j int) bool { return outcomeOrder(outs[i]) < outcomeOrder(outs[j]) })
		rows = append(rows, []string{code(a), codeList(outs)})
	}
	table(&b, []string{"Action", "Outcomes"}, rows)

	b.WriteString("## Verbs\n\n")
	rows = nil
	for _, v := range audit.Verbs {
		rows = append(rows, []string{code(v), audit.VerbDocs[v]})
	}
	table(&b, []string{"Verb", "Meaning"}, rows)

	b.WriteString("## Outcomes\n\n")
	rows = nil
	for _, o := range audit.Outcomes {
		rows = append(rows, []string{code(o), audit.OutcomeDocs[o]})
	}
	table(&b, []string{"Outcome", "Meaning"}, rows)

	b.WriteString("## Details\n\nA fixed set of typed keys; each is its own field on the log line. They never hold a secret " +
		"value, a YAML body, a password or a token. **Type** is the Elasticsearch type in `deploy/elk`.\n\n")
	rows = nil
	for _, k := range sortedKeys(audit.DetailKeys) {
		rows = append(rows, []string{code(k), string(audit.DetailKeys[k]), code(logging.ECSField(k)), audit.DetailDocs[k]})
	}
	table(&b, []string{"Key", "Type", "ECS", "Meaning"}, rows)
	return b.String(), nil
}

func outcomeOrder(o string) int {
	for i, v := range audit.Outcomes {
		if v == o {
			return i
		}
	}
	return len(audit.Outcomes)
}

// ── Reading the audit actions from the code ──────────────────────────────────
//
// An event is a models.AuditLog composite literal. Its Verb, ResourceType,
// Action and Outcome are constants (audit.VerbList, audit.KindUser, "pod"),
// audit.Kind("nodes"), or names that are followed back: a local variable to
// its assignments, a parameter to the arguments of every call of the function
// (recursively). A field that can't be followed fails docgen with its
// position, so the handlers keep their audit actions readable.

const anyKube = "<resource>"

type fn struct {
	decl   *ast.FuncDecl
	params []string
}

type scanner struct {
	fset    *token.FileSet
	consts  map[string]string // "audit.VerbList" and package-level names → value
	funcs   map[string]*fn    // by name (methods and functions)
	calls   map[string][]call // callee name → call sites
	errs    []string
	actions map[string]map[string]bool
}

type call struct {
	caller *fn
	args   []ast.Expr
}

func scanAuditActions(auditDir string, dirs ...string) (map[string]map[string]bool, error) {
	s := &scanner{fset: token.NewFileSet(), consts: map[string]string{}, funcs: map[string]*fn{},
		calls: map[string][]call{}, actions: map[string]map[string]bool{}}
	auditFiles, err := s.parseDir(auditDir)
	if err != nil {
		return nil, err
	}
	for _, f := range auditFiles {
		s.collectConsts(f, "audit.")
	}
	var files []*ast.File
	for _, d := range dirs {
		fs, err := s.parseDir(d)
		if err != nil {
			return nil, err
		}
		for _, f := range fs {
			s.collectConsts(f, "")
		}
		files = append(files, fs...)
	}
	for _, f := range files {
		for _, d := range f.Decls {
			if fd, ok := d.(*ast.FuncDecl); ok && fd.Body != nil {
				info := &fn{decl: fd}
				for _, p := range fd.Type.Params.List {
					for _, n := range p.Names {
						info.params = append(info.params, n.Name)
					}
				}
				s.funcs[fd.Name.Name] = info
			}
		}
	}
	for _, info := range s.funcs {
		info := info
		ast.Inspect(info.decl.Body, func(n ast.Node) bool {
			if c, ok := n.(*ast.CallExpr); ok {
				if name := calleeName(c.Fun); name != "" {
					s.calls[name] = append(s.calls[name], call{info, c.Args})
				}
			}
			return true
		})
	}
	for _, info := range s.funcs {
		info := info
		ast.Inspect(info.decl.Body, func(n ast.Node) bool {
			if lit, ok := n.(*ast.CompositeLit); ok && isAuditLog(lit.Type) {
				s.event(info, lit)
			}
			return true
		})
	}
	if len(s.errs) > 0 {
		sort.Strings(s.errs)
		return nil, fmt.Errorf("audit events docgen can't follow (use constants):\n  %s", strings.Join(s.errs, "\n  "))
	}
	return s.actions, nil
}

func (s *scanner) parseDir(dir string) ([]*ast.File, error) {
	paths, err := filepath.Glob(filepath.Join(dir, "*.go"))
	if err != nil {
		return nil, err
	}
	sort.Strings(paths)
	var out []*ast.File
	for _, p := range paths {
		if strings.HasSuffix(p, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(s.fset, p, nil, 0)
		if err != nil {
			return nil, err
		}
		out = append(out, f)
	}
	return out, nil
}

func (s *scanner) collectConsts(f *ast.File, prefix string) {
	for _, d := range f.Decls {
		gd, ok := d.(*ast.GenDecl)
		if !ok || gd.Tok != token.CONST {
			continue
		}
		for _, spec := range gd.Specs {
			vs := spec.(*ast.ValueSpec)
			for i, n := range vs.Names {
				if i < len(vs.Values) {
					if lit, ok := vs.Values[i].(*ast.BasicLit); ok && lit.Kind == token.STRING {
						v, _ := strconv.Unquote(lit.Value)
						s.consts[prefix+n.Name] = v
					}
				}
			}
		}
	}
}

func calleeName(e ast.Expr) string {
	switch f := e.(type) {
	case *ast.Ident:
		return f.Name
	case *ast.SelectorExpr:
		return f.Sel.Name
	}
	return ""
}

func isAuditLog(t ast.Expr) bool {
	sel, ok := t.(*ast.SelectorExpr)
	if !ok {
		return false
	}
	pkg, ok := sel.X.(*ast.Ident)
	return ok && pkg.Name == "models" && sel.Sel.Name == "AuditLog"
}

// event records the actions one AuditLog literal can produce.
func (s *scanner) event(in *fn, lit *ast.CompositeLit) {
	fields := map[string]ast.Expr{}
	for _, el := range lit.Elts {
		if kv, ok := el.(*ast.KeyValueExpr); ok {
			if k, ok := kv.Key.(*ast.Ident); ok {
				fields[k.Name] = kv.Value
			}
		}
	}
	pos := s.fset.Position(lit.Pos())
	where := fmt.Sprintf("%s:%d", filepath.Base(pos.Filename), pos.Line)

	// Fields assigned later on the variable the literal is stored in (e.Outcome = …).
	later, varName := s.laterAssignments(in, lit)

	var kinds, verbs []string
	if a, ok := fields["Action"]; ok {
		for _, v := range s.values(in, a, where+" Action", 0) {
			i := strings.LastIndex(v, ".")
			if i < 0 {
				s.errs = append(s.errs, where+": Action "+strconv.Quote(v)+" is not <type>.<verb>")
				continue
			}
			kinds, verbs = append(kinds, v[:i]), append(verbs, v[i+1:])
		}
	} else {
		verbs = s.field(in, fields, later, "Verb", where, nil)
		kinds = s.field(in, fields, later, "ResourceType", where, nil)
	}
	outcomes := s.field(in, fields, later, "Outcome", where, []string{audit.Success})
	if _, set := fields["Outcome"]; !set {
		if len(later["Outcome"]) > 0 {
			outcomes = append(outcomes, audit.Success) // the branch that doesn't set it
		}
		// A helper that takes the event and sets its outcome (denyAPIKey).
		if passed := s.passedOutcome(in, lit, varName, where); len(passed) > 0 {
			if varName == "" {
				outcomes = passed
			} else {
				outcomes = dedupe(append(outcomes, passed...))
			}
		}
	}
	for i := range verbs {
		for j := range kinds {
			if fields["Action"] != nil && i != j {
				continue
			}
			action := kinds[j] + "." + verbs[i]
			if s.actions[action] == nil {
				s.actions[action] = map[string]bool{}
			}
			for _, o := range outcomes {
				s.actions[action][o] = true
			}
		}
	}
}

// field returns the values of a literal field, plus later assignments; def
// when it is set nowhere.
func (s *scanner) field(in *fn, fields map[string]ast.Expr, later map[string][]ast.Expr, name, where string, def []string) []string {
	var out []string
	if e, ok := fields[name]; ok {
		out = append(out, s.values(in, e, where+" "+name, 0)...)
	}
	for _, e := range later[name] {
		out = append(out, s.values(in, e, where+" "+name, 0)...)
	}
	if len(out) == 0 {
		if def == nil {
			s.errs = append(s.errs, where+": "+name+" is not set")
		}
		return def
	}
	return dedupe(out)
}

// laterAssignments finds `v.Field = expr` in the function for the variable
// the literal is assigned to (`v := models.AuditLog{…}`).
func (s *scanner) laterAssignments(in *fn, lit *ast.CompositeLit) (map[string][]ast.Expr, string) {
	out := map[string][]ast.Expr{}
	var name string
	ast.Inspect(in.decl.Body, func(n ast.Node) bool {
		if as, ok := n.(*ast.AssignStmt); ok {
			for i, r := range as.Rhs {
				if r == lit && i < len(as.Lhs) {
					if id, ok := as.Lhs[i].(*ast.Ident); ok {
						name = id.Name
					}
				}
			}
		}
		return true
	})
	if name == "" {
		return out, ""
	}
	ast.Inspect(in.decl.Body, func(n ast.Node) bool {
		if as, ok := n.(*ast.AssignStmt); ok && len(as.Lhs) == len(as.Rhs) {
			for i, l := range as.Lhs {
				if sel, ok := l.(*ast.SelectorExpr); ok {
					if id, ok := sel.X.(*ast.Ident); ok && id.Name == name {
						out[sel.Sel.Name] = append(out[sel.Sel.Name], as.Rhs[i])
					}
				}
			}
		}
		return true
	})
	return out, name
}

// values returns the constant strings e can hold in function in.
func (s *scanner) values(in *fn, e ast.Expr, what string, depth int) []string {
	if depth > 8 {
		s.errs = append(s.errs, what+": too deep")
		return nil
	}
	switch x := e.(type) {
	case *ast.BasicLit:
		if x.Kind == token.STRING {
			v, _ := strconv.Unquote(x.Value)
			return []string{v}
		}
	case *ast.ParenExpr:
		return s.values(in, x.X, what, depth)
	case *ast.SelectorExpr:
		if pkg, ok := x.X.(*ast.Ident); ok {
			if v, ok := s.consts[pkg.Name+"."+x.Sel.Name]; ok {
				return []string{v}
			}
		}
	case *ast.CallExpr:
		if sel, ok := x.Fun.(*ast.SelectorExpr); ok && sel.Sel.Name == "URLParam" {
			return []string{anyKube} // chi.URLParam(r, "resource")
		}
		// audit.Kind(resource): the singular type; a resource that isn't
		// constant (a permission check for any resource) becomes <resource>.
		if sel, ok := x.Fun.(*ast.SelectorExpr); ok && sel.Sel.Name == "Kind" && len(x.Args) == 1 {
			if pkg, ok := sel.X.(*ast.Ident); ok && pkg.Name == "audit" {
				var out []string
				for _, v := range s.values(in, x.Args[0], what, depth+1) {
					out = append(out, audit.Kind(v))
				}
				return out
			}
		}
	case *ast.Ident:
		if v, ok := s.consts[x.Name]; ok {
			return []string{v}
		}
		for i, p := range in.params {
			if p != x.Name {
				continue
			}
			var out []string
			sites := s.calls[in.decl.Name.Name]
			for _, c := range sites {
				if i < len(c.args) {
					out = append(out, s.values(c.caller, c.args[i], what, depth+1)...)
				}
			}
			if len(sites) == 0 {
				return []string{anyKube} // an HTTP handler's input
			}
			return dedupe(out)
		}
		var out []string
		found := false
		ast.Inspect(in.decl.Body, func(n ast.Node) bool {
			switch st := n.(type) {
			case *ast.AssignStmt:
				if len(st.Lhs) == len(st.Rhs) {
					for i, l := range st.Lhs {
						if id, ok := l.(*ast.Ident); ok && id.Name == x.Name {
							found = true
							out = append(out, s.values(in, st.Rhs[i], what, depth+1)...)
						}
					}
				}
			case *ast.ValueSpec:
				for i, n := range st.Names {
					if n.Name == x.Name && i < len(st.Values) {
						found = true
						out = append(out, s.values(in, st.Values[i], what, depth+1)...)
					}
				}
			}
			return true
		})
		if found {
			return dedupe(out)
		}
		if vals, ok := s.closureParam(in, x, what, depth); ok {
			return vals
		}
		if s.rangeVar(in, x.Name) {
			return []string{anyKube} // for resource := range workloadKinds
		}
	}
	pos := s.fset.Position(e.Pos())
	s.errs = append(s.errs, fmt.Sprintf("%s (%s:%d in %s)", what, filepath.Base(pos.Filename), pos.Line, in.decl.Name.Name))
	return nil
}

func dedupe(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, v := range in {
		if !seen[v] {
			seen[v] = true
			out = append(out, v)
		}
	}
	return out
}

// closureParam follows a parameter of a function literal stored in a local
// variable (refuse := func(outcome, reason string) {…}) to the arguments of
// the calls of that variable in the same function.
func (s *scanner) closureParam(in *fn, id *ast.Ident, what string, depth int) ([]string, bool) {
	var out []string
	found := false
	ast.Inspect(in.decl.Body, func(n ast.Node) bool {
		as, ok := n.(*ast.AssignStmt)
		if !ok || len(as.Lhs) != len(as.Rhs) {
			return true
		}
		for i, r := range as.Rhs {
			lit, ok := r.(*ast.FuncLit)
			if !ok || id.Pos() < lit.Pos() || id.Pos() > lit.End() {
				continue
			}
			name, ok := as.Lhs[i].(*ast.Ident)
			if !ok {
				continue
			}
			idx := -1
			k := 0
			for _, p := range lit.Type.Params.List {
				for _, pn := range p.Names {
					if pn.Name == id.Name {
						idx = k
					}
					k++
				}
			}
			if idx < 0 {
				continue
			}
			found = true
			ast.Inspect(in.decl.Body, func(m ast.Node) bool {
				if c, ok := m.(*ast.CallExpr); ok {
					if f, ok := c.Fun.(*ast.Ident); ok && f.Name == name.Name && idx < len(c.Args) {
						out = append(out, s.values(in, c.Args[idx], what, depth+1)...)
					}
				}
				return true
			})
		}
		return true
	})
	return dedupe(out), found
}

// rangeVar reports whether name is the key or value of a range loop in in.
func (s *scanner) rangeVar(in *fn, name string) bool {
	found := false
	ast.Inspect(in.decl.Body, func(n ast.Node) bool {
		if rs, ok := n.(*ast.RangeStmt); ok {
			for _, e := range []ast.Expr{rs.Key, rs.Value} {
				if id, ok := e.(*ast.Ident); ok && id.Name == name {
					found = true
				}
			}
		}
		return true
	})
	return found
}

// passedOutcome: when the literal is passed to a function that sets the
// parameter's Outcome (e.Outcome = audit.Denied), the outcomes it sets.
func (s *scanner) passedOutcome(in *fn, lit *ast.CompositeLit, varName, where string) []string {
	var out []string
	ast.Inspect(in.decl.Body, func(n ast.Node) bool {
		c, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		for i, a := range c.Args {
			callee := s.funcs[calleeName(c.Fun)]
			id, isVar := a.(*ast.Ident)
			if (a != lit && !(isVar && varName != "" && id.Name == varName)) || callee == nil || i >= len(callee.params) {
				continue
			}
			param := callee.params[i]
			ast.Inspect(callee.decl.Body, func(m ast.Node) bool {
				if as, ok := m.(*ast.AssignStmt); ok && len(as.Lhs) == len(as.Rhs) {
					for j, l := range as.Lhs {
						if sel, ok := l.(*ast.SelectorExpr); ok && sel.Sel.Name == "Outcome" {
							if id, ok := sel.X.(*ast.Ident); ok && id.Name == param {
								out = append(out, s.values(callee, as.Rhs[j], where+" Outcome", 0)...)
							}
						}
					}
				}
				return true
			})
		}
		return true
	})
	return dedupe(out)
}
