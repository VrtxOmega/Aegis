"""
Aegis — Defense Systems API
Active countermeasure modules inspired by Gravity Omega defense systems.

Modules:
  1. Aegis Shield    — Egress firewall (Windows Firewall rules)
  2. Shadow Trap     — Honeypot listener (decoy port detection)
  3. Mirror Gate     — Payload/connection logging and analysis
  4. Sentinel        — Active threat neutralization (process kill, quarantine)
"""
import os
import json
import time
import socket
import threading
import subprocess
import shutil
import psutil
from datetime import datetime
from flask import Blueprint, jsonify, request

defense_bp = Blueprint('defense', __name__)

# ═══════════════════════════════════════════════════
# MODULE STATE
# ═══════════════════════════════════════════════════
_defense_state = {
    'aegis_shield': {
        'active': False,
        'rules_count': 0,
        'blocked': [],
        'description': 'Egress firewall — blocks unauthorized outbound connections'
    },
    'shadow_trap': {
        'active': False,
        'ports': [],
        'detections': [],
        'description': 'Deception layer — honeypot trap for intrusion detection'
    },
    'mirror_gate': {
        'active': False,
        'captures': [],
        'description': 'Adversarial reflection — logs attack payloads for analysis'
    },
    'sentinel': {
        'active': False,
        'kills': [],
        'quarantined': [],
        'description': 'Active threat neutralization engine'
    }
}

QUARANTINE_DIR = os.path.join(os.environ.get('LOCALAPPDATA', '.'), 'AegisProtect', 'quarantine')
TRAP_LOG_DIR = os.path.join(os.environ.get('LOCALAPPDATA', '.'), 'AegisProtect', 'trap_logs')

# Ensure directories exist
os.makedirs(QUARANTINE_DIR, exist_ok=True)
os.makedirs(TRAP_LOG_DIR, exist_ok=True)

# Shadow Trap honeypot threads
_trap_threads = {}
_trap_running = {}


# ═══════════════════════════════════════════════════
# 1. AEGIS SHIELD — Egress Firewall
# ═══════════════════════════════════════════════════

def _add_firewall_rule(name, action, direction, port=None, program=None, remote_ip=None):
    """Add a Windows Firewall rule via netsh."""
    cmd = ['netsh', 'advfirewall', 'firewall', 'add', 'rule',
           f'name=AegisShield_{name}', f'action={action}', f'dir={direction}']
    if port:
        cmd.extend([f'remoteport={port}', 'protocol=tcp'])
    if program:
        cmd.extend([f'program={program}'])
    if remote_ip:
        cmd.extend([f'remoteip={remote_ip}'])
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
        return result.returncode == 0
    except Exception:
        return False


def _remove_aegis_rules():
    """Remove all AegisShield firewall rules."""
    try:
        subprocess.run(
            ['netsh', 'advfirewall', 'firewall', 'delete', 'rule', 'name=AegisShield_*'],
            capture_output=True, text=True, timeout=5
        )
    except Exception:
        pass


# ═══════════════════════════════════════════════════
# 2. SHADOW TRAP — Honeypot Listener
# ═══════════════════════════════════════════════════

def _honeypot_listener(port):
    """Listen on a decoy port and log any connection attempts."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.settimeout(2.0)
        sock.bind(('0.0.0.0', port))
        sock.listen(5)

        while _trap_running.get(port, False):
            try:
                client, addr = sock.accept()
                detection = {
                    'port': port,
                    'source_ip': addr[0],
                    'source_port': addr[1],
                    'timestamp': datetime.now().isoformat(),
                    'type': 'connection_attempt'
                }
                _defense_state['shadow_trap']['detections'].append(detection)

                # Log to file
                log_file = os.path.join(TRAP_LOG_DIR, f"trap_{port}.jsonl")
                with open(log_file, 'a') as f:
                    f.write(json.dumps(detection) + '\n')

                # Try to capture initial data
                try:
                    client.settimeout(2.0)
                    data = client.recv(1024)
                    if data:
                        detection['payload_hex'] = data.hex()[:200]
                        detection['payload_ascii'] = data.decode('ascii', errors='replace')[:200]
                        _defense_state['mirror_gate']['captures'].append(detection)
                except Exception:
                    pass
                finally:
                    client.close()
            except socket.timeout:
                continue
            except Exception:
                break
        sock.close()
    except Exception:
        pass


def _start_trap(port):
    """Start a honeypot on a given port."""
    if port in _trap_threads and _trap_running.get(port, False):
        return False
    _trap_running[port] = True
    t = threading.Thread(target=_honeypot_listener, args=(port,),
                        daemon=True, name=f'aegis-trap-{port}')
    t.start()
    _trap_threads[port] = t
    if port not in _defense_state['shadow_trap']['ports']:
        _defense_state['shadow_trap']['ports'].append(port)
    return True


def _stop_trap(port):
    """Stop a honeypot on a given port."""
    _trap_running[port] = False
    if port in _defense_state['shadow_trap']['ports']:
        _defense_state['shadow_trap']['ports'].remove(port)
    return True


# Default trap ports (commonly probed / attack framework defaults)
DEFAULT_TRAP_PORTS = [8080, 8443, 3389, 445, 22, 23]


# ═══════════════════════════════════════════════════
# 4. SENTINEL — Active Neutralization
# ═══════════════════════════════════════════════════

def _kill_process(pid):
    """Kill a process by PID."""
    try:
        proc = psutil.Process(pid)
        name = proc.name()
        proc.kill()
        record = {
            'pid': pid,
            'name': name,
            'timestamp': datetime.now().isoformat(),
            'action': 'killed'
        }
        _defense_state['sentinel']['kills'].append(record)
        return True, name
    except (psutil.NoSuchProcess, psutil.AccessDenied) as e:
        return False, str(e)


def _quarantine_file(filepath):
    """Move a file to quarantine directory."""
    try:
        if not os.path.exists(filepath):
            return False, "File not found"
        basename = os.path.basename(filepath)
        ts = datetime.now().strftime('%Y%m%d_%H%M%S')
        dest = os.path.join(QUARANTINE_DIR, f"{ts}_{basename}")
        shutil.move(filepath, dest)
        record = {
            'original_path': filepath,
            'quarantine_path': dest,
            'timestamp': datetime.now().isoformat(),
            'action': 'quarantined'
        }
        _defense_state['sentinel']['quarantined'].append(record)
        return True, dest
    except Exception as e:
        return False, str(e)


# ═══════════════════════════════════════════════════
# API ENDPOINTS
# ═══════════════════════════════════════════════════

@defense_bp.route('/status')
def defense_status():
    """Get status of all defense systems."""
    return jsonify(_defense_state)


@defense_bp.route('/shield/engage', methods=['POST'])
def engage_shield():
    """Engage Aegis Shield — block known malicious outbound ports."""
    blocked = []
    malicious_ports = [4444, 5555, 1337, 31337, 8888, 6666, 12345, 54321]
    for port in malicious_ports:
        success = _add_firewall_rule(f'block_{port}', 'block', 'out', port=str(port))
        if success:
            blocked.append(port)

    _defense_state['aegis_shield']['active'] = True
    _defense_state['aegis_shield']['rules_count'] = len(blocked)
    _defense_state['aegis_shield']['blocked'] = blocked

    return jsonify({
        'status': 'engaged',
        'rules_added': len(blocked),
        'blocked_ports': blocked,
        'timestamp': datetime.now().isoformat()
    })


@defense_bp.route('/shield/disengage', methods=['POST'])
def disengage_shield():
    """Disengage Aegis Shield — remove all AegisShield firewall rules."""
    _remove_aegis_rules()
    _defense_state['aegis_shield']['active'] = False
    _defense_state['aegis_shield']['rules_count'] = 0
    _defense_state['aegis_shield']['blocked'] = []

    return jsonify({
        'status': 'disengaged',
        'timestamp': datetime.now().isoformat()
    })


@defense_bp.route('/trap/activate', methods=['POST'])
def activate_trap():
    """Activate Shadow Trap — start honeypot listeners on decoy ports."""
    data = request.get_json()
    ports = data.get('ports', DEFAULT_TRAP_PORTS) if data else DEFAULT_TRAP_PORTS

    started = []
    for port in ports:
        if _start_trap(port):
            started.append(port)

    _defense_state['shadow_trap']['active'] = True

    return jsonify({
        'status': 'activated',
        'ports': started,
        'timestamp': datetime.now().isoformat()
    })


@defense_bp.route('/trap/deactivate', methods=['POST'])
def deactivate_trap():
    """Deactivate Shadow Trap — stop all honeypot listeners."""
    for port in list(_trap_running.keys()):
        _stop_trap(port)

    _defense_state['shadow_trap']['active'] = False
    _defense_state['shadow_trap']['ports'] = []

    return jsonify({
        'status': 'deactivated',
        'timestamp': datetime.now().isoformat()
    })


@defense_bp.route('/trap/detections')
def trap_detections():
    """Get all honeypot detection events."""
    return jsonify({
        'detections': _defense_state['shadow_trap']['detections'],
        'total': len(_defense_state['shadow_trap']['detections'])
    })


@defense_bp.route('/mirror/status')
def mirror_status():
    """Get Mirror Gate capture status."""
    return jsonify({
        'active': _defense_state['mirror_gate']['active'],
        'captures': _defense_state['mirror_gate']['captures'][-50:],  # Last 50
        'total_captures': len(_defense_state['mirror_gate']['captures'])
    })


@defense_bp.route('/mirror/activate', methods=['POST'])
def activate_mirror():
    """Activate Mirror Gate — enable payload capture logging."""
    _defense_state['mirror_gate']['active'] = True
    return jsonify({'status': 'activated', 'timestamp': datetime.now().isoformat()})


@defense_bp.route('/mirror/deactivate', methods=['POST'])
def deactivate_mirror():
    """Deactivate Mirror Gate."""
    _defense_state['mirror_gate']['active'] = False
    return jsonify({'status': 'deactivated', 'timestamp': datetime.now().isoformat()})


@defense_bp.route('/sentinel/activate', methods=['POST'])
def activate_sentinel():
    """Activate Sentinel — enable active neutralization."""
    _defense_state['sentinel']['active'] = True
    return jsonify({'status': 'activated', 'timestamp': datetime.now().isoformat()})


@defense_bp.route('/sentinel/deactivate', methods=['POST'])
def deactivate_sentinel():
    """Deactivate Sentinel."""
    _defense_state['sentinel']['active'] = False
    return jsonify({'status': 'deactivated', 'timestamp': datetime.now().isoformat()})


@defense_bp.route('/sentinel/kill', methods=['POST'])
def sentinel_kill():
    """Kill a process by PID (requires Sentinel to be active)."""
    if not _defense_state['sentinel']['active']:
        return jsonify({'error': 'Sentinel is not active. Activate first.'}), 403

    data = request.get_json()
    pid = data.get('pid') if data else None
    if not pid:
        return jsonify({'error': 'No PID provided'}), 400

    success, result = _kill_process(int(pid))
    return jsonify({
        'success': success,
        'process': result,
        'timestamp': datetime.now().isoformat()
    })


@defense_bp.route('/sentinel/quarantine', methods=['POST'])
def sentinel_quarantine():
    """Quarantine a file (requires Sentinel to be active)."""
    if not _defense_state['sentinel']['active']:
        return jsonify({'error': 'Sentinel is not active. Activate first.'}), 403

    data = request.get_json()
    filepath = data.get('path') if data else None
    if not filepath:
        return jsonify({'error': 'No file path provided'}), 400

    success, result = _quarantine_file(filepath)
    return jsonify({
        'success': success,
        'result': result,
        'timestamp': datetime.now().isoformat()
    })
