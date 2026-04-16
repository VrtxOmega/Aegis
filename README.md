# AEGIS PROTECT

> Sovereign endpoint security and system-integrity command center for the Omega Universe operator stack.

![VERITAS Omega](https://img.shields.io/badge/VERITAS-%CE%A9-gold.svg?style=for-the-badge&colorA=000000&colorB=d4af37)
![Status](https://img.shields.io/badge/Status-ACTIVE-brightgreen?style=flat-square&colorA=000000)
![License](https://img.shields.io/badge/License-MIT-lightgrey?style=flat-square)
![Platform](https://img.shields.io/badge/Platform-Windows-0078D6?style=flat-square)

---

## Ecosystem Canon

Aegis Protect is the security and integrity layer of the VERITAS Omega sovereign operator stack. It operates entirely local — no cloud telemetry, no external model calls, no off-device data transmission — enforcing the Omega principle that sovereign infrastructure does not report to outside authorities. Aegis consumes threat intelligence from the host OS, cross-correlates it with static code analysis, and routes AI-assisted synthesis through a locally managed Ollama instance. Within the broader Omega Universe, Aegis functions as the trust-enforcement boundary: other nodes such as omega-brain-mcp and veritas-vault depend on the posture assertions Aegis produces. It is a tool for operators, not end users, and its output is audit-grade by design.

---

## Overview

**What it is**

Aegis Protect is a self-contained Electron + Flask desktop application that provides:

- Static code vulnerability scanning (regex and AST-based, offline)
- Live system threat hunting against 40+ deterministic signatures across 11 execution categories
- Process-to-network correlation for multi-vector threat narrative construction
- Real-time hardware telemetry (CPU, GPU, memory, disk, battery, thermals)
- Companion daemon lifecycle management (Ollama, VPN, hardware monitors)
- Atomic file remediation with multi-level backup chaining
- One-click PDF audit dossier generation (Veritas Compliance Report)

**What it is not**

Aegis is not an antivirus, not a network firewall, not a cloud SIEM, and not a managed detection and response (MDR) service. It does not replace endpoint protection platforms. It is an operator-grade local intelligence and remediation workbench.

---

## Capabilities

The following capabilities reflect what is implemented in the current codebase.

### Threat Hunting

| Capability | Detail |
|---|---|
| Rule engine | 40+ signatures across 11 categories: Persistence, Privilege Escalation, Payload Delivery, Lateral Movement, Evasion, Credential Access, Discovery, Collection, C2, Impact, Execution |
| Live correlation | Cross-links anomalous processes with open network connections and scan findings |
| Process telemetry | Real-time psutil-based process enumeration with parent/child chain inspection |
| LOLBin detection | Pattern matching against known living-off-the-land binary abuse signatures |

### Code Scanner

| Capability | Detail |
|---|---|
| Secret detection | Hardcoded API keys, tokens, passwords via regex patterns |
| Dangerous functions | OS command injection vectors, unsafe deserialization, network binding exposure |
| Dependency hygiene | Unpinned dependency detection across Python and JavaScript manifests |
| Remediation | Closed-loop suggest-verify-resolve workflow with atomic `_safe_write_file()` and `.aegis.bak` / `.bak.1` backup chains |
| Scan history | Persisted scan records in `aegis_scan_history.db` for regression tracking |

### AI Analysis

| Capability | Detail |
|---|---|
| Model | `qwen2.5:7b` via local Ollama instance (`http://127.0.0.1:11434`) |
| Isolation | Zero external network calls; inference is fully air-gapped |
| Prompt hardening | Input sanitization and length-guards to resist prompt injection from malicious file contents or manipulated telemetry |
| BSOD Watchdog | Background thread monitors specific kernel driver conflicts (e.g., VirtualBox NDIS filter) |

### Hardware Telemetry

| Capability | Detail |
|---|---|
| Metrics | CPU, GPU, memory, disk, battery, thermal pressure |
| Tuning | Power and cooling profile management via ThrottleStop, MSI Center, Afterburner (MSI GE78HX native) |
| Dashboard | Tab-aware polling UI to minimize resource consumption during background scanning |

### Reporting

| Capability | Detail |
|---|---|
| Format | PDF audit dossier via `veritas_pdf.py` |
| Content | Scanned assets, found vulnerabilities, threat correlations, system compliance status |
| Branding | Veritas Compliance Report, operator-stamped |

---

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                     AEGIS PROTECT                           │
│                   Electron Shell (Node)                     │
│                                                             │
│  ┌──────────────────────────────────────────────────────┐  │
│  │  Renderer Process  (src/renderer/)                   │  │
│  │  renderer.js · renderer_tasks.js                     │  │
│  │  renderer_system_status.js · renderer_weather_widget │  │
│  │  renderer_task_board.js · renderer_project_launcher  │  │
│  │  Tab-aware polling · IPC bridge via preload.js        │  │
│  └─────────────────────┬────────────────────────────────┘  │
│                         │ IPC (contextBridge)               │
│  ┌──────────────────────▼────────────────────────────────┐  │
│  │  Main Process  (src/main.js)                          │  │
│  │  Electron BrowserWindow · child_process spawn         │  │
│  │  Launches backend/app.py via Python                   │  │
│  └─────────────────────┬────────────────────────────────┘  │
│                         │ HTTP REST (localhost:5000)        │
└─────────────────────────┼───────────────────────────────────┘
                           │
┌─────────────────────────▼───────────────────────────────────┐
│                  Flask Backend  (backend/app.py)            │
│               Waitress · 128 threads · 127.0.0.1:5000       │
│                                                             │
│  /api/system      system_api.py    (OS metrics)             │
│  /api/security    security_api.py  (security checks)        │
│  /api/threats     threat_api.py    (threat hunt engine)     │
│  /api/ai          ai_engine.py     (Ollama AI synthesis)    │
│  /api/defense     defense_api.py   (active defense ops)     │
│  /api/scanner     scanner_api.py   (code vulnerability scan)│
│  /api/hardware    hardware_api.py  (telemetry)              │
│  /api/performance perf_api.py      (CPU/GPU/mem)            │
│  /api/tuning      tuning_api.py    (power/cooling profiles) │
│  /api/vpn         vpn_api.py       (VPN lifecycle)          │
│  /api/weather     weather_api.py   (local weather proxy)    │
│  /api/projects    projects_api.py  (project management)     │
│  report_api.py                     (PDF report generation)  │
│  correlation_api.py                (cross-signal correlation)│
│  lifecycle_api.py                  (companion daemon mgmt)  │
│                                                             │
│  ┌──────────────┐  ┌──────────────────┐                    │
│  │  aegis.db    │  │ aegis_scan_      │                    │
│  │  (telemetry) │  │ history.db       │                    │
│  └──────────────┘  └──────────────────┘                    │
└─────────────────────────────────────────────────────────────┘
                           │
              ┌────────────▼───────────┐
              │  Companion Daemons     │
              │  Ollama  (localhost    │
              │  :11434) — on-demand  │
              │  ThrottleStop          │
              │  MSI Afterburner       │
              └────────────────────────┘
```

---

## Quickstart

### Prerequisites

| Requirement | Notes |
|---|---|
| Windows 10/11 (64-bit) | Primary supported platform |
| Node.js >= 18 | For Electron shell |
| Python >= 3.11 | For Flask backend |
| Ollama | Required for AI synthesis; install from [ollama.com](https://ollama.com) |

Pull the required Ollama model before first run:

```
ollama pull qwen2.5:7b
```

### Development

```bat
REM 1. Install Node dependencies
npm install

REM 2. Install Python dependencies (backend)
pip install -r backend/requirements.txt

REM 3. Launch Electron + auto-spawned Flask backend
npm start
```

`npm start` invokes `electron .` which uses `src/main.js` as the entry point. The main process spawns `backend/app.py` automatically as a child process.

### Build / Package

```bat
REM Portable Windows executable (AegisProtect.exe)
npm run build

REM Full Windows installer
npm run dist
```

Build artifacts are emitted to the `dist/` directory. The `asar` bundle is disabled so backend Python files remain accessible at runtime.

---

## Configuration

### Environment Variables

| Variable | Default | Purpose |
|---|---|---|
| `OLLAMA_HOST` | `http://127.0.0.1:11434` | Override Ollama API base URL |
| `AEGIS_BACKEND_PORT` | `5000` | Flask listen port (change in `backend/app.py` if needed) |

### Key Config Paths (Windows)

| Path | Purpose |
|---|---|
| `backend/aegis.db` | Primary SQLite database (telemetry, tasks) |
| `backend/aegis_scan_history.db` | Scan result history |
| `backend/schema.sql` | Database schema; applied by `init_db.py` |
| `src/assets/icon.ico` | Application icon used for Windows packaging |

### Companion Tool Paths

The lifecycle manager (`backend/lifecycle_manager.py`) expects managed companions to be resolvable on `PATH` or at default install locations:

- `ollama` — standard Ollama install
- `ThrottleStop` — MSI GE78HX tuning (optional; only needed for power profile management)
- `MSI Afterburner` — GPU tuning (optional)

---

## Security and Privacy Posture

**Data residency:** All scan data, telemetry, threat findings, and AI-generated analyses remain on-device. No data leaves the host.

**AI isolation:** The `ai_engine.py` blueprint routes all inference to the local Ollama endpoint (`127.0.0.1:11434`). No external model API calls are made.

**Prompt hardening:** User-controllable inputs (file paths, file contents, process names) that reach the AI prompt layer are sanitized and length-bounded before injection. This reduces the blast radius of adversarially crafted files designed to manipulate the AI output.

**Atomic writes:** All file remediation operations use `_safe_write_file()`, which writes to a staging path and renames atomically. Backup chains (`.aegis.bak`, `.bak.1`) are maintained before any overwrite.

**Local binding only:** The Flask backend binds exclusively to `127.0.0.1:5000`. It is not reachable from external network interfaces.

**What is not guaranteed:** Aegis does not provide kernel-level tamper protection, signed binary verification, or hardware root-of-trust attestation. It is not a replacement for a full endpoint detection and response (EDR) solution.

---

## Threat Model

### Trust Boundaries

```
[ Operator (local user) ]
        |
        v
[ Electron Shell — IPC/contextBridge ]  <-- trust boundary 1
        |
        v
[ Flask Backend — localhost:5000 ]      <-- trust boundary 2
        |
        +---> [ SQLite databases ]
        |
        +---> [ Ollama — localhost:11434 ]
        |
        +---> [ Host OS APIs (psutil, subprocess) ]
```

### In Scope

- **Malicious file contents:** Files scanned by the code scanner may contain adversarially crafted strings designed to manipulate regex results or inject into AI prompts. Aegis applies sanitization to mitigate this.
- **Compromised Ollama model outputs:** AI-generated text is treated as untrusted and rendered as plain text; it is never executed.
- **Path traversal in scanner:** The scanner enforces bounds checks to prevent scanning outside the designated project directories.
- **Multi-threaded data races in the backend:** Covered by destruction campaign tests (Wave 1 & 2).

### Out of Scope

- **Physical access attacks:** Aegis does not protect against an attacker with physical access to the machine.
- **Kernel/hypervisor compromises:** Below the OS abstraction layer Aegis operates on.
- **Supply chain attacks on Ollama or Python packages:** Operator is responsible for verifying dependency integrity.
- **Network-level attacks from external hosts:** The backend is localhost-only; external network attack surface is zero by design.
- **Other users on the same host:** Aegis is a single-operator tool; multi-user isolation is not implemented.

---

## Roadmap

| Item | Status |
|---|---|
| Static code scanner + closed-loop remediation | Implemented |
| Live threat hunt engine (40+ signatures) | Implemented |
| Process-network correlation engine | Implemented |
| AI synthesis via local Ollama | Implemented |
| Hardware telemetry dashboard | Implemented |
| Companion daemon lifecycle manager | Implemented |
| PDF audit report generation | Implemented |
| BSOD watchdog | Implemented |
| Cross-platform support (macOS / Linux) | Planned |
| Veritas Vault integration for encrypted finding storage | Planned |
| omega-brain-mcp protocol bridge for distributed threat correlation | Planned |
| Headless / server-mode operation | Planned |
| Formal threat intelligence feed ingestion (STIX/TAXII) | Planned |

---

## Omega Universe Cross-Links

Aegis Protect is one node in the VERITAS Omega sovereign operator ecosystem. Related repositories:

| Repository | Role |
|---|---|
| [omega-brain-mcp](https://github.com/VrtxOmega/omega-brain-mcp) | Central MCP reasoning hub; planned consumer of Aegis posture data |
| [veritas-vault](https://github.com/VrtxOmega/veritas-vault) | Encrypted sovereign secret and credential store |
| [Ollama-Omega](https://github.com/VrtxOmega/Ollama-Omega) | MCP bridge that exposes local Ollama models to any IDE |
| [drift](https://github.com/VrtxOmega/drift) | Drift detection and configuration change tracking |
| [SovereignMedia](https://github.com/VrtxOmega/SovereignMedia) | Sovereign local media and content management |
| [sovereign-arcade](https://github.com/VrtxOmega/sovereign-arcade) | Front-facing operator showcase for the Omega stack |

---

## License

MIT License. See [LICENSE](LICENSE) for full terms.

Copyright (c) 2026 RJ Lopez / VrtxOmega
