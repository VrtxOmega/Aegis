"""
VPN status detection for Aegis.
Detects Proton VPN connection state via multiple strategies:
  1. Get-NetAdapter — find active VPN tunnel adapters (WireGuard/TAP/Wintun)
  2. Process scan — detect running ProtonVPN services
  3. Get-NetIPAddress — pull tunnel IP from the adapter
Falls back gracefully through each strategy.
The native Proton VPN app handles connect/disconnect — this is read-only monitoring.
"""
import json
import subprocess
import urllib.request
import psutil
from flask import Blueprint, jsonify

vpn_bp = Blueprint('vpn', __name__)

# Adapter name patterns that indicate a VPN tunnel
VPN_ADAPTER_PATTERNS = ['protonvpn', 'wireguard', 'wintun', 'tap-', 'openvpn', 'nordlynx']

# Process names that indicate a VPN is running
VPN_PROCESS_NAMES = {
    'protonvpn.client', 'protonvpn.wireguardservice', 'protonvpnservice',
    'openvpn', 'wireguard', 'nordvpn', 'nordlynx',
}


def _detect_vpn_adapter():
    """Use Get-NetAdapter to find active VPN tunnel adapters.
    This works for WireGuard tunnels that ipconfig misses."""
    try:
        cmd = (
            "Get-NetAdapter | Where-Object { $_.Status -eq 'Up' } | "
            "Select-Object Name, InterfaceDescription, Status | "
            "ConvertTo-Json -Compress"
        )
        result = subprocess.run(
            ['powershell', '-NoProfile', '-Command', cmd],
            capture_output=True, text=True, timeout=8
        )
        if result.returncode != 0 or not result.stdout.strip():
            return None

        data = json.loads(result.stdout)
        if not isinstance(data, list):
            data = [data]

        for adapter in data:
            name = (adapter.get('Name') or '').lower()
            desc = (adapter.get('InterfaceDescription') or '').lower()
            combined = f"{name} {desc}"
            if any(p in combined for p in VPN_ADAPTER_PATTERNS):
                return adapter.get('Name')

    except Exception:
        pass
    return None


def _get_tunnel_ip(adapter_name):
    """Get the IPv4 tunnel IP from a named adapter via Get-NetIPAddress."""
    try:
        cmd = (
            f"Get-NetIPAddress -InterfaceAlias '{adapter_name}' -AddressFamily IPv4 "
            f"-ErrorAction SilentlyContinue | Select-Object IPAddress | ConvertTo-Json -Compress"
        )
        result = subprocess.run(
            ['powershell', '-NoProfile', '-Command', cmd],
            capture_output=True, text=True, timeout=5
        )
        if result.returncode == 0 and result.stdout.strip():
            data = json.loads(result.stdout)
            if isinstance(data, list):
                data = data[0]
            ip = data.get('IPAddress', '')
            if ip and not ip.startswith('169.254'):
                return ip
    except Exception:
        pass
    return None


def _detect_vpn_process():
    """Scan running processes for VPN services."""
    found = {}
    for proc in psutil.process_iter(['pid', 'name']):
        try:
            pname = (proc.info['name'] or '').lower().replace('.exe', '')
            if pname in VPN_PROCESS_NAMES:
                found[pname] = proc.info['pid']
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    return found


def _get_public_ip():
    """Get current public IP via API."""
    try:
        req = urllib.request.Request('https://api.ipify.org?format=json',
                                     headers={'User-Agent': 'AegisProtect/2.1'})
        with urllib.request.urlopen(req, timeout=5) as resp:
            data = json.loads(resp.read())
            return data.get('ip', 'unknown')
    except Exception:
        return None


def _identify_provider(adapter_name, processes):
    """Determine which VPN provider is active."""
    name_lower = (adapter_name or '').lower()
    proc_names = set(processes.keys()) if processes else set()

    if 'protonvpn' in name_lower or any('protonvpn' in p for p in proc_names):
        return 'Proton VPN'
    if 'nordlynx' in name_lower or any('nordvpn' in p for p in proc_names):
        return 'NordVPN'
    if 'wireguard' in name_lower:
        return 'WireGuard'
    if 'openvpn' in name_lower or 'tap-' in name_lower:
        return 'OpenVPN'
    return 'VPN'


def _detect_protocol(adapter_name):
    """Detect the VPN protocol from the adapter description."""
    if not adapter_name:
        return None
    try:
        cmd = (
            f"(Get-NetAdapter -Name '{adapter_name}' -ErrorAction SilentlyContinue)"
            f".InterfaceDescription"
        )
        result = subprocess.run(
            ['powershell', '-NoProfile', '-Command', cmd],
            capture_output=True, text=True, timeout=5
        )
        desc = result.stdout.strip().lower()
        if 'wireguard' in desc:
            return 'WireGuard'
        if 'tap' in desc or 'openvpn' in desc:
            return 'OpenVPN'
        if 'wintun' in desc:
            return 'WireGuard'
        return desc.title() if desc else None
    except Exception:
        return None


@vpn_bp.route('/status', methods=['GET'])
def vpn_status():
    """Detect VPN connection state from network adapters + processes."""
    # Strategy 1: Find active VPN adapter
    adapter_name = _detect_vpn_adapter()

    # Strategy 2: Check for VPN processes
    vpn_procs = _detect_vpn_process()

    # Determine connection state
    tunnel_ip = None
    protocol = None
    if adapter_name:
        tunnel_ip = _get_tunnel_ip(adapter_name)
        protocol = _detect_protocol(adapter_name)

    # Connected if we have an active adapter with an IP
    connected = adapter_name is not None and tunnel_ip is not None

    # Even without adapter IP, if WireGuard service is running, check harder
    if not connected and vpn_procs:
        # VPN processes running but no adapter found — process running but not connected
        # (e.g., ProtonVPN client open but not connected to a server)
        pass

    provider = _identify_provider(adapter_name, vpn_procs) if (adapter_name or vpn_procs) else None
    public_ip = _get_public_ip() if connected else None

    return jsonify({
        'connected': connected,
        'tunnel_ip': tunnel_ip,
        'public_ip': public_ip,
        'provider': provider,
        'protocol': protocol,
        'adapter': adapter_name,
        'services': list(vpn_procs.keys()) if vpn_procs else [],
    })
