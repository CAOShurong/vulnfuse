# Security policy

## Supported versions

VulnFuse is currently an initial alpha. Security fixes target the latest tagged release and `main`; older alpha releases may not receive backports.

## Private reporting

Please use GitHub's **Report a vulnerability** button on the repository Security page. This creates a private advisory visible to maintainers.

Include:

- affected release or commit;
- deployment mode: browser, CLI, Action, or core library;
- minimal reproduction using synthetic data;
- security impact and required attacker position;
- any suggested mitigation.

Do not include live credentials, customer reports, proprietary source, or a public zero-day proof of concept. If a sensitive report structure is essential, replace its values while preserving the parser shape.

## Response targets

The project aims to acknowledge credible reports within seven days and provide an assessment or next step within fourteen days. These are targets, not a service-level agreement.

## Scope notes

Correlation disagreement alone is usually a correctness issue, not a security vulnerability, unless it crosses a documented trust boundary or enables evidence suppression, code execution, data disclosure, or filesystem impact.

The following are important but generally outside project control:

- a malicious browser extension reading page content;
- a compromised GitHub runner or hosting origin;
- a scanner report already containing secrets;
- a user explicitly opening an untrusted HTTP(S) advisory link;
- resource exhaustion above documented limits or after limits are intentionally raised.

See [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) for the full boundary.
