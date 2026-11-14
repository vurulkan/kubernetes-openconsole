package api

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// TestMetricsListEverySeries keeps the docs' Metrics page complete: every
// openconsole_* series named in this package's code is in Metrics, and the
// other way round.
func TestMetricsListEverySeries(t *testing.T) {
	listed := map[string]bool{}
	for _, m := range Metrics {
		listed[m.Name] = true
		if m.Help == "" || (m.Type != "counter" && m.Type != "gauge") {
			t.Errorf("%s: needs help text and type counter or gauge", m.Name)
		}
	}
	files, _ := filepath.Glob("*.go")
	seen := map[string]bool{}
	series := regexp.MustCompile(`"(openconsole_[a-z_]+)`)
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		src, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		for _, m := range series.FindAllStringSubmatch(string(src), -1) {
			seen[m[1]] = true
			if !listed[m[1]] {
				t.Errorf("%s writes %s: add it to Metrics", f, m[1])
			}
		}
	}
	for name := range listed {
		if !seen[name] {
			t.Errorf("Metrics lists %s, but nothing writes it", name)
		}
	}
}
