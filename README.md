# Aegis Protect 
*(formerly Aegis Home Base)*

![Aegis Protect Banner](https://img.shields.io/badge/VERITAS-%CE%A9-gold.svg?style=for-the-badge&colorA=000000&colorB=d4af37)
![Status](https://img.shields.io/badge/Status-AUDIT--READY-success)
![Version](https://img.shields.io/badge/Version-v2.5.0-blue)

**Aegis Protect** is a comprehensive, standalone Electron + Flask security platform designed for extreme high-assurance environment monitoring, active threat hunting, and hardware lifecycle management. Combining deterministic static analysis with dynamic process correlation and LLM-assisted threat evaluation (Ollama), Aegis provides a unified command center over system integrity.

## Core Pillars

### 1. Advanced Threat Hunting & Code Scanning
- **Project Scanner**: Deep offline vulnerability static analysis (AST & Regex) targeting secret leakage, supply chain dependency pinning, and dangerous function usages.
- **Threat Engine**: Evaluates live system state against 40+ deterministic threat signatures spanning 11 execution categories (Persistence, Privilege Escalation, Payload Delivery, Evasion).
- **Correlation Engine**: Dynamically cross-links anomalous processes with open network connections, recent code findings, and persistence registries to construct multi-vector threat narratives.

### 2. High-Assurance AI Explanations
- Employs a local, air-gapped LLM instance (`qwen2.5:7b` via Ollama) to synthesize plain-English analyses of security signatures without ever transmitting data off-device.
- Features stringent input-sanitization and length-guards to prevent prompt-injection attacks from malicious file structures or manipulated system telemetry.

### 3. Hardware & Performance Dashboard
- **Telemetry Cockpit**: Real-time metrics for CPU, GPU, Memory, Battery, and Disk Health tracking thermal pressure limits and active system modes.
- **Tuning Management**: Controls system cooling and power profiles natively on MSI GE78HX architecture (ThrottleStop, MSI Center, Afterburner).
- **BSOD Watchdog**: Real-time monitoring of specific low-level kernel drivers (e.g., VirtualBox NDIS filter conflicts) maintaining system stability and up-time.

### 4. Veritas Omega Hardened Execution
- **Atomic Remediation & Rollbacks**: Fully shielded local rewrites utilizing `_safe_write_file()`. Features multi-level deep backup chaining (`.aegis.bak`, `.bak.1`) and real-time execution verifications.
- **Veritas Compliance Reporting**: One-click generation of fully branded `.pdf` security audit dossiers detailing scanned assets, found vulnerabilities, threat correlations, and system compliance status.

## Architecture

- **Frontend**: Custom UI interface contained in vanilla Electron (`renderer.js`, HTML, standard CSS) leveraging a smart "Tab-Aware" polling mechanism to guarantee interface fluidity alongside heavy background metric ingestion.
- **Backend Stack**: Flask running multithreaded via `Waitress` across 128 worker threads on `127.0.0.1:5000`. Exposes over 70 compartmentalized REST routes across independent endpoints (`security_api`, `threat_api`, `defense_api`, `perf_api`, etc.).
- **Persistence Layer**: Lightweight, self-contained SQLite integration (`aegis.db`, `aegis_scan_history.db`) for long-term telemetry retention and correlation tracking.
- **Companion Lifecycle Manager**: Granular subsystem daemon lifecycle control dictating start and stop procedures across local sub-systems (Ollama background API, VPN protocols, Hardware monitors).

## Security & Verification

This platform has undergone the rigorous sequence of **Destruction Campaign** adversarial tests:
1. **Wave 1 & 2**: Evaluated system-level caching limits, AI output length exhaustion attacks, and multi-threaded data race survival metrics.
2. **AI Narrative Validation**: Strict regression checks testing raw JSON payload ingestion logic against malformed context attempts.
3. **Execution Fencing**: Path-traversal bounds testing ensures `.bak` restoration locks and static analysis reading stays perfectly inside target dimensions.

## License
Copyright © 2026. All rights reserved.
