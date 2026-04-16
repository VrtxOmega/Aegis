# Contributing to Aegis Protect

Aegis Protect is part of the VERITAS Omega sovereign operator stack. Contributions are welcome from operators aligned with the project's design principles.

## Design Principles

- **Local-first, always.** No capability may introduce external data transmission without explicit operator consent.
- **Deterministic over probabilistic.** Threat signatures and scanner rules must be reproducible and explainable.
- **Minimal surface.** Additions should earn their place. Prefer extending existing APIs over introducing new dependency trees.
- **Audit-grade output.** Any change that affects report generation, scan findings, or telemetry must be verifiable.

## Workflow

1. Fork the repository and create a feature branch from `main`.
2. Make changes. Keep commits focused and atomic.
3. For backend changes, confirm the Flask app starts cleanly and the affected API routes respond correctly.
4. For frontend changes, verify the Electron shell loads and the relevant tab renders correctly.
5. Run any existing tests in `backend/` and the root directory before opening a pull request.
6. Open a pull request against `main` with a clear description of what changed and why.

## Commit Style

Use the imperative mood in commit subjects. Example: `Add path-traversal guard to scanner_api`.

Keep subjects under 72 characters. Include context in the body when the reason for a change is not self-evident from the diff.

## Reporting Issues

Open a GitHub issue with:
- Operating system and version
- Node.js version (`node --version`)
- Python version (`python --version`)
- Steps to reproduce
- Expected vs. observed behavior

For security-relevant issues, follow the process in [SECURITY.md](SECURITY.md).
