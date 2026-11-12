package api

import (
	_ "embed"
	"net/http"

	"sigs.k8s.io/yaml"
)

// openapiYAML is the hand-written API description (M16). openapi_test.go fails when a
// route in routes() is missing from it, or it names a route that doesn't exist.
//
//go:embed openapi.yaml
var openapiYAML []byte

// openapiJSON is converted once; the file is embedded, so a broken one fails the tests, not a user.
var openapiJSON = func() []byte {
	b, err := yaml.YAMLToJSON(openapiYAML)
	if err != nil {
		panic("openapi.yaml: " + err.Error())
	}
	return b
}()

// handleOpenAPI serves the description without sign-in: it holds paths and
// permissions only (no hostname, user or secret), and an agent reads it first.
func handleOpenAPI(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(openapiJSON)
}
