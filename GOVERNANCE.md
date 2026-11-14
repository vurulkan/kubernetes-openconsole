# Governance

Kubernetes OpenConsole is an open-source project licensed under [Apache-2.0](LICENSE). This document says who makes
decisions and how. It aims to follow the practices the [CNCF](https://www.cncf.io/) expects of its projects, and it
will change as the community grows.

## Roles

- **Users** run OpenConsole and report bugs, ask questions and propose features in
  [GitHub issues](https://github.com/vurulkan/kubernetes-openconsole/issues).
- **Contributors** send pull requests: code, documentation (English and Turkish), translations, tests, reviews. See
  [CONTRIBUTING.md](CONTRIBUTING.md).
- **Maintainers** ([MAINTAINERS.md](MAINTAINERS.md)) review and merge, decide what goes into a release, publish
  releases and images, handle security reports ([SECURITY.md](SECURITY.md)) and enforce the
  [Code of Conduct](CODE_OF_CONDUCT.md).

## Decisions

- Day-to-day changes are decided in pull requests by **lazy consensus**: a change that a maintainer approved and that no
  maintainer objected to within a reasonable time (normally three working days for larger changes) can be merged.
- Larger changes (new features that change permissions, the audit model, the API or storage; new dependencies with a
  large footprint; breaking changes) start as an issue describing the problem and the proposal, so users can comment
  before code is written.
- If maintainers disagree, they discuss it in the issue or pull request. If they still disagree, a simple majority of
  maintainers decides; while there are fewer than three maintainers, the project lead decides and writes down why.
- Security fixes may be prepared in private and merged without the usual waiting time ([SECURITY.md](SECURITY.md)).

## Becoming a maintainer

A contributor becomes a maintainer after sustained, quality contributions over several months (code, reviews, docs or
issue triage) and a demonstrated understanding of the project's security model. An existing maintainer nominates them
in a pull request to [MAINTAINERS.md](MAINTAINERS.md); it is accepted if no maintainer objects within two weeks (or by
majority vote if one does). Maintainers who are inactive for six months, or who ask to step down, move to the emeritus
list.

## Releases

Releases follow semantic versioning (`MAJOR.MINOR.PATCH`). Only the CI of this repository publishes images, from a
signed release tag, with build provenance and an SBOM (see
[Verify the image](https://k8sopenconsole.github.io/installation/verify-image)). The documentation is versioned per
minor release.

## Changes to this document

Changes to this governance are made by pull request and need the approval of a majority of maintainers (while there is
a single maintainer, that maintainer's approval after the pull request has been open for at least one week).

## Trademarks and licensing

Code is licensed under Apache-2.0 and documentation under CC BY 4.0. The project's name and logo are covered by
[TRADEMARKS.md](TRADEMARKS.md).
