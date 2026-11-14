package config

import (
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// envRead matches the backend's ways of reading an environment variable with
// a literal name: os.Getenv / os.LookupEnv and this package's helpers.
var envRead = regexp.MustCompile(`(?:os\.Getenv|os\.LookupEnv|envOr|envBool|envIntMin|envDurationMin)\("([A-Z][A-Z0-9_]*[A-Z0-9])"`)

// TestVarsListEveryEnvRead keeps the docs' Environment variables page
// complete: a variable read anywhere in the backend must be in Vars.
func TestVarsListEveryEnvRead(t *testing.T) {
	listed := map[string]bool{}
	for _, v := range Vars {
		if listed[v.Name] {
			t.Errorf("%s listed twice", v.Name)
		}
		listed[v.Name] = true
		if v.Description == "" || !contains(Sections, v.Section) {
			t.Errorf("%s: needs a description and a section from Sections", v.Name)
		}
	}
	read := map[string]bool{}
	err := filepath.WalkDir("../..", func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return err
		}
		src, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		for _, m := range envRead.FindAllStringSubmatch(string(src), -1) {
			read[m[1]] = true
			if !listed[m[1]] {
				t.Errorf("%s reads %s: add it to config.Vars (it becomes the docs page)", path, m[1])
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	for name := range listed {
		if !read[name] {
			t.Errorf("config.Vars lists %s, but nothing reads it", name)
		}
	}
}

func contains(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}
