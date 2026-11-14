# Security policy

OpenConsole gives people access to Kubernetes clusters, so security reports get priority.

## Reporting a vulnerability

**Please don't open a public issue.** Report it privately through GitHub:
[Security → Report a vulnerability](https://github.com/vurulkan/kubernetes-openconsole/security/advisories/new).

Please include:

- the version (`GET /api/version`, or the image tag) and how OpenConsole is deployed;
- what an attacker can do, and what they need first (an account, a role, an API key, network access);
- steps to reproduce, or a proof of concept;
- any idea for a fix.

## What happens next

- We acknowledge the report within **5 working days**.
- We confirm or rule out the issue, assess its severity and agree on a disclosure date with you. The default is to
  publish within **90 days** of the report, sooner when a fix is out.
- The fix ships in a patch release; a GitHub security advisory describes the issue, the affected versions and the
  fixed version, and credits you unless you prefer otherwise.

## Supported versions

| Version | Supported |
|---|---|
| the latest minor release (currently 2.23.x) | yes |
| older releases | no: upgrade to the latest release |

## Scope

In scope: the OpenConsole server and UI, the API, the published images and the manifests in `deploy/`. Out of scope:
weaknesses of the Kubernetes clusters OpenConsole connects to, of the identity providers (LDAP, Azure AD) or of a
deployment that ignores the [hardening checklist](https://k8sopenconsole.github.io/operations/hardening). OpenConsole
is an internal operations console, not a Kubernetes security boundary; see the
[security model](https://k8sopenconsole.github.io/operations/security).
