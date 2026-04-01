"""
Correlation API — Links findings across scan domains
=====================================================
Bridges threat findings, project findings, live processes,
network connections, and scan history into a unified correlation view.
"""
import psutil
from flask import Blueprint, jsonify, request

from correlation_engine import correlate
from scan_history import get_history, get_scan_detail

correlation_bp = Blueprint('correlation', __name__)


def _get_running_processes():
    """Get a lightweight snapshot of running processes."""
    processes = []
    for proc in psutil.process_iter(['pid', 'name', 'exe', 'cmdline']):
        try:
            info = proc.info
            processes.append({
                'pid': info.get('pid'),
                'name': info.get('name', ''),
                'exe': info.get('exe', '') or '',
                'cmdline': ' '.join(info.get('cmdline') or []),
            })
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    return processes


def _get_active_connections():
    """Get active network connections."""
    connections = []
    try:
        for conn in psutil.net_connections(kind='inet'):
            connections.append({
                'laddr': {'ip': conn.laddr.ip, 'port': conn.laddr.port} if conn.laddr else {},
                'raddr': {'ip': conn.raddr.ip, 'port': conn.raddr.port} if conn.raddr else {},
                'status': conn.status,
                'pid': conn.pid,
            })
    except (psutil.AccessDenied, PermissionError):
        pass
    return connections


def _get_scan_history_for_persistence():
    """Load scan history for persistence detection."""
    try:
        scans = get_history(limit=10)
        # Build per-finding hash counts from history
        finding_history = {}
        for scan in scans:
            scan_id = scan.get('id')
            if not scan_id:
                continue
            # Get detailed findings for this scan
            detail = get_scan_detail(scan_id)
            if not detail:
                continue
            findings = detail.get('findings', [])

            for f in findings:
                fhash = f.get('hash', f.get('id', ''))
                if fhash:
                    if fhash not in finding_history:
                        finding_history[fhash] = {
                            'finding_hash': fhash,
                            'first_seen': scan.get('timestamp', ''),
                            'scan_count': 0,
                        }
                    finding_history[fhash]['scan_count'] += 1

        return list(finding_history.values())
    except Exception:
        return []


@correlation_bp.route('/api/correlate', methods=['POST'])
def correlate_endpoint():
    """Run correlation analysis across all data sources.

    Accepts optional threat_findings and project_findings in POST body.
    Automatically retrieves processes, connections, and scan history.
    """
    try:
        data = request.get_json() or {}
        threat_findings = data.get('threat_findings', [])
        project_findings = data.get('project_findings', [])

        # Gather live system state
        processes = _get_running_processes()
        connections = _get_active_connections()
        scan_history = _get_scan_history_for_persistence()

        # Run correlation
        result = correlate(
            threat_findings=threat_findings,
            project_findings=project_findings,
            processes=processes,
            connections=connections,
            scan_history=scan_history,
        )

        return jsonify(result)

    except Exception as e:
        return jsonify({
            'links': [],
            'persistent_findings': [],
            'summary': {
                'total_links': 0,
                'process_links': 0,
                'network_links': 0,
                'code_links': 0,
                'persistent_count': 0,
            },
            'error': str(e),
        })
