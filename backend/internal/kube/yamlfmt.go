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
		// than LF and TAB make block scalars illegal in YAML). Falling back
		// to the original double-quoted scalar is safer than producing
		// invalid YAML.
		if yamlStringBlockSafe(n.Value) {
			n.Style = yamlv3.LiteralStyle
		}
	}
	for _, child := range n.Content {
		walkYAMLNode(child)
	}
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
