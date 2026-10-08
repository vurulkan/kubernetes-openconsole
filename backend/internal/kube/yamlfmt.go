package kube

import (
	"bytes"
	"strings"

	yamlv3 "gopkg.in/yaml.v3"
)

// PrettifyYAML walks the YAML scalar tree and converts multi-line string
// scalars from the ugly double-quoted "line1\nline2\n" form that
// sigs.k8s.io/yaml emits into readable block scalars (|-/|). ConfigMap data
// is the obvious win — a 50-line JSON or script would otherwise come back as
// a single quoted line with every newline shown as a literal \n.
//
// Round-trips cleanly: a Decode→walk→Encode preserves field order (yaml.v3
// mapping nodes carry key/value in order) and style on nodes that don't need
// prettification.
func PrettifyYAML(raw []byte) []byte {
	var node yamlv3.Node
	if err := yamlv3.Unmarshal(raw, &node); err != nil {
		return raw
	}
	walkYAMLNode(&node)
	var buf bytes.Buffer
	enc := yamlv3.NewEncoder(&buf)
	enc.SetIndent(2)
	if err := enc.Encode(&node); err != nil {
		return raw
	}
	_ = enc.Close()
	return buf.Bytes()
}

func walkYAMLNode(n *yamlv3.Node) {
	if n == nil {
		return
	}
	// A scalar is a candidate when it contains a newline — tag has to stay
	// !!str so the output is still parseable as the original string. The
	// LiteralStyle emits `|` (or `|-` depending on trailing newline) which
	// renders every embedded newline on its own line.
	if n.Kind == yamlv3.ScalarNode && (n.Tag == "!!str" || n.Tag == "") && strings.Contains(n.Value, "\n") {
		// Skip strings that would need escaping anyway (control chars other
		// than LF and TAB make block scalars illegal in YAML).
		if yamlStringBlockSafe(n.Value) {
			// YAML spec: a block scalar line can't end with whitespace, and
			// the string as a whole can't end with trailing spaces. yaml.v3's
			// encoder silently falls back to the ugly double-quoted single-
			// liner when either rule is violated — hiding the structure for
			// values like a Spring Boot application.yml ConfigMap that end a
			// line with "boh:      ". Normalize by stripping trailing
			// whitespace from each line so the block scalar actually emits.
			// Trade-off: a handful of trailing spaces in the original value
			// are lost in the UI's YAML view; byte-for-byte fidelity is still
			// available via `kubectl get -o yaml`.
			n.Value = trimLineTrailingSpaces(n.Value)
			n.Style = yamlv3.LiteralStyle
		}
	}
	for _, child := range n.Content {
		walkYAMLNode(child)
	}
}

// trimLineTrailingSpaces removes trailing spaces / tabs from every line (and
// from the string as a whole) so the content is eligible to be emitted as a
// YAML block scalar. Interior content is untouched.
func trimLineTrailingSpaces(s string) string {
	lines := strings.Split(s, "\n")
	for i, line := range lines {
		lines[i] = strings.TrimRight(line, " \t")
	}
	return strings.Join(lines, "\n")
}

// yamlStringBlockSafe returns true when s is OK to render as a block scalar.
// LF (\n) and TAB (\t) are fine; any other control character forces a
// quoted scalar. Leading whitespace on the first line also disqualifies
// block style (needs an indent indicator we don't want to maintain).
func yamlStringBlockSafe(s string) bool {
	if s == "" {
		return false
	}
	if s[0] == ' ' || s[0] == '\t' {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == '\n' || c == '\t' {
			continue
		}
		if c < 0x20 {
			return false
		}
	}
	return true
}
