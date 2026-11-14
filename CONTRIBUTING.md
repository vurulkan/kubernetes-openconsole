# Contributing

Thanks for helping. Bug reports, fixes, features, documentation and translations are all welcome. By taking part you
agree to the [Code of Conduct](CODE_OF_CONDUCT.md). Security problems: see [SECURITY.md](SECURITY.md), not an issue.

## Before you start

- **Small fix** (a bug, a typo, a test): open a pull request directly.
- **Larger change** (a feature, anything touching permissions, the audit log, the API, storage or the deploy
  manifests): open an issue first and describe the problem and your idea, so we can agree before you write code
  ([GOVERNANCE.md](GOVERNANCE.md#decisions)).

## Developer Certificate of Origin (DCO)

Every commit must be signed off, which certifies the [Developer Certificate of Origin](https://developercertificate.org/):
that you wrote the change or have the right to submit it under the project's license.

```bash
git commit -s -m "Explain what changed"
# adds: Signed-off-by: Your Name <you@example.com>
```

Contributions are accepted under the project's licenses: Apache-2.0 for code, CC BY 4.0 for documentation.

## Working on the code

The [code map, commands and rules](CLAUDE.md) are in `CLAUDE.md` (written for people and coding agents alike). The
short version:

```bash
# backend (Go) and frontend (React + TypeScript); the same checks as CI
cd backend  && go vet ./... && go build ./... && go test -race ./...
cd frontend && npm ci && npx tsc --noEmit -p . && npm test && npm run build

# run it locally: backend on :8080, Vite on :5173
cd backend  && go run ./cmd/server
cd frontend && npm run dev
```

First sign-in is `admin` / `admin`; you are asked to change the password. Add a cluster in **Admin → Clusters** (a
throwaway [k3d](https://k3d.io/) cluster works well; see `hack/k3d/` for test workloads).

## Pull requests

- Branch from `dev` and open the pull request against `dev`. Releases go from `dev` to `main`.
- Keep a pull request to one change, with a test for new behaviour and for risky logic.
- User-visible text goes into both English and Turkish (`frontend/src/i18n.ts`; a test checks both have every key).
  New UI works in light and dark theme and with the keyboard.
- New endpoints, permissions, audit actions, environment variables, metrics and Kubernetes rights follow the
  checklist in [`CLAUDE.md`](CLAUDE.md) ("When you add …"); `go run ./cmd/docgen` regenerates the reference pages.
- Anything a user or operator notices also needs a documentation change, in English and Turkish, in
  [k8sopenconsole/k8sopenconsole.github.io](https://github.com/k8sopenconsole/k8sopenconsole.github.io).
- CI must pass. A maintainer reviews; see [GOVERNANCE.md](GOVERNANCE.md) for how decisions are made.

## Documentation and translations

The documentation site has its own repository and guide:
[k8sopenconsole/k8sopenconsole.github.io](https://github.com/k8sopenconsole/k8sopenconsole.github.io). Every page
exists in English and Turkish; Turkish follows the words of the app's Turkish UI (`i18n/tr/GLOSSARY.md` there).
