"""
Aegis — Security API Blueprint
Endpoints: processes, network, connections, startup, ports

Performance: Uses a shared system snapshot with 2s TTL.
All endpoints read from the same cached snapshot — eliminates
redundant psutil.process_iter() and psutil.net_connections() calls.
"""
import os
import time
import threading
import subprocess
import psutil
from flask import Blueprint, jsonify

security_bp = Blueprint('security', __name__)

# ═══════════════════════════════════════════
# SYSTEM SNAPSHOT CACHE (2-second TTL)
# ═══════════════════════════════════════════
# Single source of truth for all security endpoints.
# Prevents N redundant psutil calls per polling cycle.
_snapshot_lock = threading.Lock()
_snapshot = {
    'processes': [],
    'net_counters': None,
    'net_connections': [],
    'timestamp': 0
}
SNAPSHOT_TTL = 2.0  # seconds

# Suspicious path fragments — processes running from these locations get flagged
_SUSPICIOUS_PATHS = [
    '\\temp\\', '\\tmp\\', '\\downloads\\', '\\appdata\\local\\temp\\',
    '\\users\\public\\', '\\programdata\\temp\\'
]

# Known parent→child relationships that are normal
_EXPECTED_PARENTS = {
    'svchost.exe': {'services.exe'},
    'chrome.exe': {'chrome.exe', 'explorer.exe'},
    'msedge.exe': {'msedge.exe', 'explorer.exe'},
    'node.exe': {'electron.exe', 'code.exe', 'cmd.exe', 'powershell.exe', 'node.exe'},
    'electron.exe': {'node.exe', 'explorer.exe', 'electron.exe'},
    'python.exe': {'cmd.exe', 'powershell.exe', 'python.exe', 'code.exe', 'node.exe'},
    'pythonw.exe': {'python.exe', 'pythonw.exe', 'cmd.exe', 'powershell.exe'},
}


def _compute_process_flags(proc_info):
    """Compute explainable risk flags for a single process."""
    flags = []
    exe_path = proc_info.get('exe') or ''
    exe_lower = exe_path.lower()

    # Flag: running from temp/download/public directory
    for frag in _SUSPICIOUS_PATHS:
        if frag in exe_lower:
            flags.append('TEMP_PATH_EXECUTION')
            break

    # Flag: no executable path resolvable (could be injected)
    if not exe_path and proc_info.get('name', '').lower() not in ('system', 'system idle process', 'registry'):
        flags.append('NO_EXE_PATH')

    # Flag: unusual parent for this process
    name_lower = (proc_info.get('name') or '').lower()
    parent_lower = (proc_info.get('parent_name') or '').lower()
    if name_lower in _EXPECTED_PARENTS and parent_lower and parent_lower not in _EXPECTED_PARENTS[name_lower]:
        flags.append('UNUSUAL_PARENT')

    return flags


def _refresh_snapshot():
    """Refresh the shared system snapshot if stale (>2s old)."""
    now = time.time()
    if now - _snapshot['timestamp'] < SNAPSHOT_TTL:
        return  # Still fresh

    with _snapshot_lock:
        # Double-check after acquiring lock
        if now - _snapshot['timestamp'] < SNAPSHOT_TTL:
            return

        # Processes — enriched with investigation-quality fields
        proc_list = []
        for p in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_info',
                                       'status', 'exe', 'cmdline', 'username',
                                       'create_time', 'ppid']):
            try:
                info = p.info
                mem = info.get('memory_info')
                if mem is None:
                    continue

                # Resolve parent name
                parent_name = ''
                ppid = info.get('ppid')
                if ppid:
                    try:
                        parent_name = psutil.Process(ppid).name()
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        pass

                # Build cmdline string
                cmdline_raw = info.get('cmdline') or []
                cmdline_str = ' '.join(cmdline_raw) if cmdline_raw else ''

                proc_entry = {
                    'pid': info['pid'],
                    'name': info['name'] or 'Unknown',
                    'cpu_percent': round(info.get('cpu_percent', 0) or 0, 1),
                    'memory_mb': round(mem.rss / (1024 * 1024), 1),
                    'status': info.get('status', 'unknown'),
                    'exe': info.get('exe') or '',
                    'cmdline': cmdline_str[:300],  # Cap length
                    'parent_name': parent_name,
                    'username': info.get('username') or '',
                    'create_time': info.get('create_time', 0),
                }
                proc_entry['flags'] = _compute_process_flags(proc_entry)
                proc_list.append(proc_entry)
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue

        # Network
        try:
            net_counters = psutil.net_io_counters()
        except Exception:
            net_counters = None

        try:
            net_conns = psutil.net_connections(kind='inet')
        except Exception:
            net_conns = []

        _snapshot['processes'] = proc_list
        _snapshot['net_counters'] = net_counters
        _snapshot['net_connections'] = net_conns
        _snapshot['timestamp'] = time.time()


@security_bp.route('/processes')
def get_processes():
    """Top 25 processes sorted by memory — reads from shared snapshot."""
    try:
        _refresh_snapshot()
        sorted_procs = sorted(_snapshot['processes'],
                              key=lambda x: x['memory_mb'], reverse=True)[:25]
        return jsonify({'processes': sorted_procs})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@security_bp.route('/network')
def get_network():
    """Network I/O counters + connection count — reads from shared snapshot."""
    try:
        _refresh_snapshot()
        net = _snapshot['net_counters']
        conns = _snapshot['net_connections']
        if net is None:
            return jsonify({'error': 'Network counters unavailable'}), 500
        return jsonify({
            'bytes_sent': net.bytes_sent,
            'bytes_recv': net.bytes_recv,
            'packets_sent': net.packets_sent,
            'packets_recv': net.packets_recv,
            'errors_in': net.errin,
            'errors_out': net.errout,
            'connections_count': len(conns)
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@security_bp.route('/connections')
def get_connections():
    """Active network connections — reads from shared snapshot."""
    try:
        _refresh_snapshot()
        conns = _snapshot['net_connections']
        connection_list = []
        for c in conns:
            if c.status == 'ESTABLISHED' and c.raddr:
                proc_name = 'Unknown'
                try:
                    if c.pid:
                        proc_name = psutil.Process(c.pid).name()
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass
                connection_list.append({
                    'local': f"{c.laddr.ip}:{c.laddr.port}",
                    'remote': f"{c.raddr.ip}:{c.raddr.port}",
                    'status': c.status,
                    'pid': c.pid,
                    'process': proc_name
                })
        connection_list.sort(key=lambda x: x['process'].lower())
        return jsonify({'connections': connection_list[:50]})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@security_bp.route('/ports')
def get_ports():
    """Listening ports — reads from shared snapshot."""
    try:
        _refresh_snapshot()
        conns = _snapshot['net_connections']
        listening = []
        seen_ports = set()
        for c in conns:
            if c.status == 'LISTEN' and c.laddr.port not in seen_ports:
                seen_ports.add(c.laddr.port)
                proc_name = 'Unknown'
                try:
                    if c.pid:
                        proc_name = psutil.Process(c.pid).name()
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass

                # Exposure classification — conservative per audit
                addr = c.laddr.ip
                if addr in ('127.0.0.1', '::1', 'localhost'):
                    exposure = 'LOCALHOST'
                else:
                    exposure = 'NON_LOCAL'

                listening.append({
                    'port': c.laddr.port,
                    'address': addr,
                    'pid': c.pid,
                    'process': proc_name,
                    'exposure': exposure
                })
        listening.sort(key=lambda x: x['port'])
        return jsonify({'ports': listening})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@security_bp.route('/startup')
def get_startup():
    """Windows startup items from registry + startup folders."""
    def _classify_startup_risk(cmd_path):
        """Classify startup entry path risk level."""
        lower = cmd_path.lower().replace('"', '').strip()
        # System locations — expected
        system_paths = ['c:\\windows\\', 'c:\\program files\\', 'c:\\program files (x86)\\']
        for sp in system_paths:
            if lower.startswith(sp):
                return 'system'
        # Suspicious locations
        suspicious = ['\\temp\\', '\\tmp\\', '\\downloads\\', '\\users\\public\\']
        for s in suspicious:
            if s in lower:
                return 'suspicious'
        # User locations — not inherently bad but less trusted
        if '\\appdata\\' in lower or '\\users\\' in lower:
            return 'user'
        return 'user'  # Default to user for unknown paths

    try:
        items = []

        # Registry startup locations
        import winreg
        reg_paths = [
            (winreg.HKEY_LOCAL_MACHINE, r'SOFTWARE\Microsoft\Windows\CurrentVersion\Run'),
            (winreg.HKEY_CURRENT_USER, r'SOFTWARE\Microsoft\Windows\CurrentVersion\Run'),
        ]
        for hive, path in reg_paths:
            try:
                key = winreg.OpenKey(hive, path)
                i = 0
                while True:
                    try:
                        name, value, _ = winreg.EnumValue(key, i)
                        hive_name = 'HKLM' if hive == winreg.HKEY_LOCAL_MACHINE else 'HKCU'
                        items.append({
                            'name': name,
                            'command': value,
                            'source': f'{hive_name}\\Run',
                            'type': 'registry',
                            'location_risk': _classify_startup_risk(value)
                        })
                        i += 1
                    except OSError:
                        break
                winreg.CloseKey(key)
            except OSError:
                continue

        # Startup folder items
        startup_dirs = [
            os.path.expandvars(r'%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup'),
            os.path.expandvars(r'%PROGRAMDATA%\Microsoft\Windows\Start Menu\Programs\Startup'),
        ]
        for sdir in startup_dirs:
            if os.path.exists(sdir):
                for fname in os.listdir(sdir):
                    fpath = os.path.join(sdir, fname)
                    items.append({
                        'name': os.path.splitext(fname)[0],
                        'command': fpath,
                        'source': 'Startup Folder',
                        'type': 'folder',
                        'location_risk': _classify_startup_risk(fpath)
                    })

        return jsonify({'startup_items': items})
    except Exception as e:
        return jsonify({'error': str(e)}), 500
