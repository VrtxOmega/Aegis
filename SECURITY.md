# Security Policy

## Supported Versions

Only the most recent commit on the `main` branch is actively supported. No backport patches are issued for prior states.

## Reporting a Vulnerability

Do not open a public GitHub issue for security vulnerabilities.

Report security issues by emailing the maintainer directly or by using [GitHub private security advisories](https://github.com/VrtxOmega/Aegis/security/advisories/new).

Include the following in your report:

- Description of the vulnerability and its potential impact
- Steps to reproduce or a proof-of-concept
- Affected component (e.g., `scanner_api.py`, `ai_engine.py`, Electron IPC layer)
- Any suggested mitigations if you have them

## Response Expectations

Reports will be acknowledged within 5 business days. A fix or formal statement of scope (e.g., "out of scope per threat model") will be provided within 30 days where possible.

## Scope

Refer to the **Threat Model** section in [README.md](README.md) for the current in-scope and out-of-scope boundaries.

Physical access attacks, kernel-level compromises, and supply chain attacks on third-party dependencies (Ollama, Python packages, Electron) are out of scope for this policy.
