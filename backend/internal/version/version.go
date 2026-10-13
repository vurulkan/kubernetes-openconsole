// Package version holds the build version, set at link time:
//
//	go build -ldflags "-X k8s-dashboard/backend/internal/version.Version=2.15.0"
//
// Release images get it from the git tag (Dockerfile ARG VERSION).
package version

// Version is "dev" for local builds.
var Version = "dev"
