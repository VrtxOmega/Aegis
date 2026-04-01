"""
Correlation Engine — Deterministic link discovery
===================================================
Links code findings (Projects) to active processes (Security),
network connections, and scan history for persistence tracking.

Pure data function — all data passed in, no I/O, no AI.
"""
import os
import re
from datetime import datetime


def correlate(threat_findings=None, project_findings=None,
              processes=None, connections=None, scan_history=None):
    """
    Discover correlations between threat findings, project findings,
    active processes, network connections, and scan history.

    Args:
        threat_findings: list[dict] from /api/threats/scan
        project_findings: list[dict] from /api/scanner/scan
        processes: list[dict] with keys {pid, name, exe, cmdline}
        connections: list[dict] with keys {laddr, raddr, status, pid}
        scan_history: list[dict] with keys {finding_hash, first_seen, scan_count}

    Returns:
        {
            links: [{source_type, source_id, target_type, target_id, reason, confidence}],
            persistent_findings: [{finding_id, first_seen, scan_count, status}],
            summary: {total_links, process_links, network_links, code_links, persistent_count}
        }
    """
    threat_findings = threat_findings or []
    project_findings = project_findings or []
    processes = processes or []
    connections = connections or []
    scan_history = scan_history or []

    links = []

    # ── 1. Process → Code Finding correlation ──
    # If a running process exe path contains the same directory as a project finding
    links.extend(_correlate_process_to_code(processes, project_findings))

    # ── 2. Network → Threat Finding correlation ──
    # If a threat finding mentions a port/IP and an active connection uses that port
    links.extend(_correlate_network_to_threat(connections, threat_findings))

    # ── 3. Code → Threat cross-link ──
    # If a code finding and threat finding share common indicators
    links.extend(_correlate_code_to_threat(project_findings, threat_findings))

    # ── 4. History → Current persistence tracking ──
    persistent_findings = _track_persistence(
        threat_findings + project_findings, scan_history
    )

    # Deduplicate links
    seen_links = set()
    unique_links = []
    for link in links:
        key = (link['source_type'], link['source_id'],
               link['target_type'], link['target_id'])
        if key not in seen_links:
            seen_links.add(key)
            unique_links.append(link)

    # Summary
    process_links = sum(1 for l in unique_links if 'process' in l['source_type'].lower() or 'process' in l['target_type'].lower())
    network_links = sum(1 for l in unique_links if 'network' in l['source_type'].lower() or 'connection' in l['target_type'].lower())
    code_links = sum(1 for l in unique_links if 'code' in l['source_type'].lower() or 'project' in l['target_type'].lower())

    return {
        'links': unique_links,
        'persistent_findings': persistent_findings,
        'summary': {
            'total_links': len(unique_links),
            'process_links': process_links,
            'network_links': network_links,
            'code_links': code_links,
            'persistent_count': len(persistent_findings),
        }
    }


def _correlate_process_to_code(processes, project_findings):
    """Link running processes to code findings when exe path matches project directory."""
    links = []
    if not processes or not project_findings:
        return links

    # Build a map of project directories from findings
    project_dirs = {}
    for pf in project_findings:
        filepath = pf.get('file', '')
        if filepath:
            # Normalize: get the project directory (parent of the file)
            proj_dir = os.path.dirname(os.path.abspath(filepath)).lower()
            if proj_dir not in project_dirs:
                project_dirs[proj_dir] = []
            project_dirs[proj_dir].append(pf)

    for proc in processes:
        exe = (proc.get('exe') or '').lower()
        cmdline = (proc.get('cmdline') or '').lower()
        proc_id = f"pid:{proc.get('pid', '?')}"

        for proj_dir, findings_in_dir in project_dirs.items():
            # Check if process exe or cmdline references this project directory
            if proj_dir in exe or proj_dir in cmdline:
                for finding in findings_in_dir:
                    links.append({
                        'source_type': 'process',
                        'source_id': proc_id,
                        'target_type': 'project_finding',
                        'target_id': finding.get('id', finding.get('hash', '')),
                        'reason': f"Process {proc.get('name', '?')} (PID {proc.get('pid', '?')}) is running from the same directory as finding: {finding.get('title', '?')}",
                        'confidence': 0.75,
                        'process_name': proc.get('name', '?'),
                        'finding_title': finding.get('title', '?'),
                    })

    return links


def _correlate_network_to_threat(connections, threat_findings):
    """Link active network connections to threat findings mentioning the same port/IP."""
    links = []
    if not connections or not threat_findings:
        return links

    # Extract ports and IPs from active connections
    active_ports = set()
    active_remote_ips = set()
    conn_by_port = {}

    for conn in connections:
        laddr = conn.get('laddr', {})
        raddr = conn.get('raddr', {})

        local_port = laddr.get('port') if isinstance(laddr, dict) else None
        if local_port:
            active_ports.add(str(local_port))
            conn_by_port[str(local_port)] = conn

        remote_ip = raddr.get('ip') if isinstance(raddr, dict) else None
        if remote_ip and remote_ip not in ('0.0.0.0', '127.0.0.1', '::1', '::'):
            active_remote_ips.add(remote_ip)

    # Search threat findings for port/IP references
    port_pattern = re.compile(r'port\s*[:#]?\s*(\d{2,5})', re.I)
    ip_pattern = re.compile(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})')

    for tf in threat_findings:
        detail = tf.get('detail', '') + ' ' + tf.get('title', '') + ' ' + tf.get('recommendation', '')

        # Check for port matches
        for port_match in port_pattern.findall(detail):
            if port_match in active_ports:
                conn = conn_by_port.get(port_match, {})
                links.append({
                    'source_type': 'connection',
                    'source_id': f"port:{port_match}",
                    'target_type': 'threat_finding',
                    'target_id': tf.get('id', ''),
                    'reason': f"Active connection on port {port_match} matches threat finding: {tf.get('title', '?')}",
                    'confidence': 0.85,
                    'port': port_match,
                    'finding_title': tf.get('title', '?'),
                })

        # Check for IP matches
        for ip_match in ip_pattern.findall(detail):
            if ip_match in active_remote_ips and ip_match not in ('0.0.0.0', '127.0.0.1'):
                links.append({
                    'source_type': 'connection',
                    'source_id': f"ip:{ip_match}",
                    'target_type': 'threat_finding',
                    'target_id': tf.get('id', ''),
                    'reason': f"Active connection to {ip_match} matches threat finding: {tf.get('title', '?')}",
                    'confidence': 0.90,
                    'remote_ip': ip_match,
                    'finding_title': tf.get('title', '?'),
                })

    return links


def _correlate_code_to_threat(project_findings, threat_findings):
    """Link code findings to threat findings via shared indicators."""
    links = []
    if not project_findings or not threat_findings:
        return links

    # Define indicator keywords for cross-linking
    indicator_map = {
        'Exposed Binding': ['0.0.0.0', 'network', 'exposed', 'binding', 'listener'],
        'Dangerous Function': ['eval', 'exec', 'injection', 'code execution'],
        'Hardcoded Secret': ['credential', 'password', 'secret', 'token', 'key'],
    }

    for pf in project_findings:
        pf_category = pf.get('category', '')
        pf_title = pf.get('title', '').lower()
        indicators = indicator_map.get(pf_category, [])

        for tf in threat_findings:
            tf_detail = (tf.get('detail', '') + ' ' + tf.get('title', '')).lower()

            for indicator in indicators:
                if indicator.lower() in pf_title and indicator.lower() in tf_detail:
                    links.append({
                        'source_type': 'project_finding',
                        'source_id': pf.get('id', pf.get('hash', '')),
                        'target_type': 'threat_finding',
                        'target_id': tf.get('id', ''),
                        'reason': f"Code finding '{pf.get('title', '?')}' shares indicator '{indicator}' with threat: {tf.get('title', '?')}",
                        'confidence': 0.70,
                        'indicator': indicator,
                        'code_title': pf.get('title', '?'),
                        'threat_title': tf.get('title', '?'),
                    })
                    break  # One link per pair is sufficient

    return links


def _track_persistence(all_findings, scan_history):
    """Cross-reference current findings with scan history to detect persistent issues."""
    persistent = []
    if not scan_history:
        return persistent

    # Build history lookup by finding hash
    history_map = {}
    for h in scan_history:
        fhash = h.get('finding_hash', '')
        if fhash:
            history_map[fhash] = h

    for finding in all_findings:
        fhash = finding.get('hash', finding.get('id', ''))
        if fhash in history_map:
            hist = history_map[fhash]
            scan_count = hist.get('scan_count', 1)
            first_seen = hist.get('first_seen', '')

            if scan_count >= 2:
                persistent.append({
                    'finding_id': fhash,
                    'finding_title': finding.get('title', '?'),
                    'category': finding.get('category', '?'),
                    'first_seen': first_seen,
                    'scan_count': scan_count,
                    'status': 'persistent' if scan_count >= 3 else 'recurring',
                })

    return persistent
