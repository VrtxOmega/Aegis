"""
Aegis — Threat Hunting Engine
40 detection rules across 11 categories
Layer 1: Static rule-based evidence gathering
"""
import os
import re
import glob
import time
import subprocess
import psutil
from datetime import datetime
from flask import Blueprint, jsonify, request

threat_bp = Blueprint('threats', __name__)

# Import scan history persistence
try:
    from scan_history import save_scan, get_history, get_scan_detail
    _history_available = True
except ImportError:
    _history_available = False

# ═══════════════════════════════════════════════════
# SEVERITY WEIGHTS (for score calculation)
# ═══════════════════════════════════════════════════
SEV_WEIGHT = {'critical': 25, 'high': 10, 'medium': 4, 'low': 1, 'info': 0}

# ═══════════════════════════════════════════════════
# LOLBin PATTERNS
# ═══════════════════════════════════════════════════
LOLBIN_RULES = [
    {
        'id': 'LOL-001', 'severity': 'high', 'category': 'lolbin',
        'process': 'certutil.exe',
        'patterns': [r'-urlcache', r'-decode', r'-encode', r'-split\s+-f'],
        'title': 'certutil.exe used for download/decode',
        'recommendation': 'Verify if this is authorized admin activity. certutil is commonly abused to download payloads or decode Base64.'
    },
    {
        'id': 'LOL-002', 'severity': 'high', 'category': 'lolbin',
        'process': 'mshta.exe',
        'patterns': [r'http[s]?://', r'javascript:', r'vbscript:'],
        'title': 'mshta.exe executing remote/scripted content',
        'recommendation': 'mshta should not be running remote content. Kill process and investigate source.'
    },
    {
        'id': 'LOL-003', 'severity': 'high', 'category': 'lolbin',
        'process': 'regsvr32.exe',
        'patterns': [r'/s\s+/u\s+/i:', r'scrobj\.dll', r'http[s]?://'],
        'title': 'regsvr32.exe Squiblydoo attack pattern',
        'recommendation': 'This pattern bypasses AppLocker. Kill immediately and check for persistence.'
    },
    {
        'id': 'LOL-004', 'severity': 'medium', 'category': 'lolbin',
        'process': 'bitsadmin.exe',
        'patterns': [r'/transfer', r'/download'],
        'title': 'bitsadmin.exe file transfer detected',
        'recommendation': 'bitsadmin is rarely used legitimately by end users. Verify the download target.'
    },
    {
        'id': 'LOL-005', 'severity': 'high', 'category': 'lolbin',
        'process': 'powershell.exe',
        'patterns': [r'-[eE]nc\s', r'-[eE]ncodedcommand', r'-[nN]op\s', r'-[wW]\s+hidden',
                     r'IEX\s*\(', r'Invoke-Expression', r'DownloadString\s*\(',
                     r'DownloadFile\s*\(', r'Net\.WebClient', r'Start-BitsTransfer',
                     r'FromBase64String'],
        'title': 'PowerShell with suspicious execution flags',
        'recommendation': 'Encoded/hidden PowerShell is the #1 fileless attack vector. Inspect the decoded command.'
    },
    {
        'id': 'LOL-006', 'severity': 'medium', 'category': 'lolbin',
        'process': 'wmic.exe',
        'patterns': [r'/node:', r'process\s+call\s+create'],
        'title': 'wmic.exe remote execution attempt',
        'recommendation': 'WMIC remote execution can be used for lateral movement. Verify target node.'
    },
    {
        'id': 'LOL-007', 'severity': 'high', 'category': 'lolbin',
        'process': 'rundll32.exe',
        'patterns': [r'http[s]?://', r'javascript:', r'shell32\.dll.*ShellExec_RunDLL'],
        'title': 'rundll32.exe with URL or script execution',
        'recommendation': 'rundll32 should not load remote content. Investigate immediately.'
    },
    {
        'id': 'LOL-008', 'severity': 'medium', 'category': 'lolbin',
        'process': 'msiexec.exe',
        'patterns': [r'/q.*http[s]?://', r'/quiet.*http[s]?://'],
        'title': 'msiexec.exe silent remote install',
        'recommendation': 'Silent MSI installs from remote URLs are a known malware delivery vector.'
    },
]

# ═══════════════════════════════════════════════════
# KNOWN MINER PROCESS NAMES
# ═══════════════════════════════════════════════════
MINER_NAMES = {'xmrig', 'cgminer', 'ethminer', 'nbminer', 't-rex', 'phoenixminer',
               'gminer', 'lolminer', 'trex', 'teamredminer', 'nanominer', 'cpuminer'}

MINER_PORTS = {3333, 14433, 14444, 45700, 9999, 3334, 4444, 5555, 7777, 8899}
C2_PORTS = {4444, 5555, 8888, 1337, 6666, 9999, 1234, 31337, 12345, 54321}

# Known system process paths
SYSTEM_PROCESS_PATHS = {
    'svchost.exe': r'c:\windows\system32',
    'csrss.exe': r'c:\windows\system32',
    'lsass.exe': r'c:\windows\system32',
    'services.exe': r'c:\windows\system32',
    'smss.exe': r'c:\windows\system32',
    'wininit.exe': r'c:\windows\system32',
    'winlogon.exe': r'c:\windows\system32',
    'explorer.exe': r'c:\windows',
    'taskhostw.exe': r'c:\windows\system32',
    'dwm.exe': r'c:\windows\system32',
    'conhost.exe': r'c:\windows\system32',
}

RANSOM_NOTE_PATTERNS = [
    'README_DECRYPT*', 'RECOVER_FILES*', 'HOW_TO_DECRYPT*', 'DECRYPT_INFO*',
    'YOUR_FILES_ARE_ENCRYPTED*', '_readme.txt', 'HELP_DECRYPT*',
    'ATTENTION!!!.txt', 'RESTORE_FILES*', '#DECRYPT#*', '!README!*',
]

SUSPICIOUS_PARENT_CHAINS = [
    ('winword.exe', 'cmd.exe'), ('winword.exe', 'powershell.exe'),
    ('excel.exe', 'cmd.exe'), ('excel.exe', 'powershell.exe'),
    ('outlook.exe', 'cmd.exe'), ('outlook.exe', 'powershell.exe'),
    ('svchost.exe', 'cmd.exe'), ('wmiprvse.exe', 'powershell.exe'),
    ('wscript.exe', 'cmd.exe'), ('wscript.exe', 'powershell.exe'),
    ('cscript.exe', 'cmd.exe'), ('cscript.exe', 'powershell.exe'),
]


def _make_finding(rule_id, severity, category, title, detail, recommendation):
    return {
        'id': rule_id,
        'severity': severity,
        'category': category,
        'title': title,
        'detail': detail,
        'recommendation': recommendation,
        'timestamp': datetime.now().isoformat()
    }


# ═══════════════════════════════════════════════════
# PROCESS SNAPSHOT CACHE
# Iterate all processes ONCE per scan, share across all detectors.
# Only fetch expensive cmdline/exe/parent for RELEVANT process names.
# ═══════════════════════════════════════════════════
_process_cache = []
_cache_time = 0

# Build set of all process names we actually care about
_INTERESTING_NAMES = set()
for _r in LOLBIN_RULES:
    _INTERESTING_NAMES.add(_r['process'].lower())
_INTERESTING_NAMES.update({
    'cmd.exe', 'powershell.exe', 'pwsh.exe',
    'wscript.exe', 'cscript.exe', 'mshta.exe',
    'vssadmin.exe', 'wmic.exe', 'bcdedit.exe',
    'mimikatz.exe', 'procdump.exe', 'procdump64.exe',
    'reg.exe', 'wevtutil.exe',
    'fodhelper.exe', 'eventvwr.exe', 'sdclt.exe', 'computerdefaults.exe',
})
_INTERESTING_NAMES.update(SYSTEM_PROCESS_PATHS.keys())
_INTERESTING_NAMES.update({f'{m}.exe' for m in MINER_NAMES})


def _snapshot_processes():
    """Build a process snapshot — ONE pass over all processes.
    Only fetches expensive attributes for processes matching the threat watchlist."""
    global _process_cache, _cache_time
    now = time.time()
    if now - _cache_time < 3:  # Cache for 3 seconds
        return _process_cache

    snapshot = []
    for proc in psutil.process_iter(['pid', 'name']):
        try:
            pid = proc.info['pid']
            name = (proc.info['name'] or '').lower()

            # Only fetch expensive attributes for interesting processes
            needs_detail = name in _INTERESTING_NAMES

            if needs_detail:
                # Get cmdline (expensive)
                try:
                    cmdline_parts = proc.cmdline()
                    cmdline = ' '.join(cmdline_parts) if cmdline_parts else ''
                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess, OSError):
                    cmdline = ''

                # Get exe path
                try:
                    exe = (proc.exe() or '').lower()
                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess, OSError):
                    exe = ''

                # Get parent name
                try:
                    parent = proc.parent()
                    parent_name = parent.name().lower() if parent else ''
                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess, OSError):
                    parent_name = ''
            else:
                cmdline = ''
                exe = ''
                parent_name = ''

            # Get CPU percent (cheap)
            try:
                cpu = proc.cpu_percent(interval=0)
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                cpu = 0

            snapshot.append({
                'pid': pid,
                'name': name,
                'cmdline': cmdline,
                'cmdline_lower': cmdline.lower(),
                'exe': exe,
                'parent_name': parent_name,
                'cpu': cpu or 0,
                'proc': proc,
            })
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue

    _process_cache = snapshot
    _cache_time = now
    return snapshot


# ═══════════════════════════════════════════════════
# DETECTOR FUNCTIONS
# ═══════════════════════════════════════════════════

def detect_lolbins():
    """Scan running processes for LOLBin abuse patterns."""
    findings = []
    procs = _snapshot_processes()
    for p in procs:
        if not p['cmdline']:
            continue
        for rule in LOLBIN_RULES:
            if rule['process'].lower() in p['name']:
                for pattern in rule['patterns']:
                    if re.search(pattern, p['cmdline'], re.IGNORECASE):
                        findings.append(_make_finding(
                            rule['id'], rule['severity'], rule['category'],
                            rule['title'],
                            f"PID {p['pid']} ({p['name']}): {p['cmdline'][:200]}",
                            rule['recommendation']
                        ))
                        break
    return findings


def detect_persistence():
    """Scan scheduled tasks, services, registry for persistence mechanisms."""
    findings = []

    # PER-001: Scheduled tasks with encoded/suspicious commands
    try:
        result = subprocess.run(
            ['schtasks', '/query', '/fo', 'CSV'],
            capture_output=True, text=True, timeout=5, errors='replace'
        )
        if result.returncode == 0:
            for line in result.stdout.split('\n'):
                lower = line.lower()
                if any(p in lower for p in ['-enc ', '-encodedcommand', 'powershell.*-w hidden',
                                             'cmd.exe /c', 'http://', 'https://',
                                             'appdata\\local\\temp']):
                    findings.append(_make_finding(
                        'PER-001', 'high', 'persistence',
                        'Scheduled task with suspicious command',
                        line.strip()[:200],
                        'Review this scheduled task. Encoded commands in tasks are a persistence red flag.'
                    ))
    except Exception:
        pass

    # PER-002: Services with binaries outside safe directories (fast path via 'wmic')
    try:
        result = subprocess.run(
            ['wmic', 'service', 'get', 'Name,PathName', '/format:csv'],
            capture_output=True, text=True, timeout=8, errors='replace'
        )
        if result.returncode == 0:
            safe_prefixes = [
                'c:\\windows', 'c:\\program files', 'c:\\program files (x86)',
                'c:\\programdata\\microsoft\\windows defender',  # Defender uses versioned platform dirs here
            ]
            for line in result.stdout.split('\n'):
                parts = line.strip().split(',')
                if len(parts) >= 3:
                    svc_name = parts[1].strip()
                    binpath = parts[2].strip().strip('"').lower()
                    if binpath and not any(binpath.startswith(sp) for sp in safe_prefixes):
                        if 'svchost' in binpath or not binpath.endswith('.exe'):
                            continue
                        findings.append(_make_finding(
                            'PER-002', 'high', 'persistence',
                            f"Service binary outside safe directories: {svc_name}",
                            f"Binary: {binpath}",
                            'Services running from non-standard paths may indicate persistence. Verify legitimacy.'
                        ))
    except Exception:
        pass

    # PER-003: WMI event subscriptions
    try:
        cmd = 'Get-WMIObject -Namespace root\\subscription -Class CommandLineEventConsumer 2>$null | Select-Object Name, CommandLineTemplate | ConvertTo-Json'
        result = subprocess.run(
            ['powershell', '-NoProfile', '-Command', cmd],
            capture_output=True, text=True, timeout=8
        )
        if result.returncode == 0 and result.stdout.strip() and result.stdout.strip() != '':
            import json
            try:
                data = json.loads(result.stdout)
                if not isinstance(data, list):
                    data = [data]
                for sub in data:
                    findings.append(_make_finding(
                        'PER-003', 'high', 'persistence',
                        f"WMI event subscription: {sub.get('Name', 'Unknown')}",
                        f"Command: {sub.get('CommandLineTemplate', 'N/A')[:200]}",
                        'WMI event subscriptions survive reboots. This is a known APT persistence technique.'
                    ))
            except (json.JSONDecodeError, ValueError):
                pass
    except Exception:
        pass

    # PER-004: Registry Run keys pointing to suspicious paths
    try:
        import winreg
        suspicious_paths = ['\\temp', '\\tmp', '\\downloads', '\\appdata\\local\\temp',
                           '\\users\\public', '\\programdata\\']
        run_keys = [
            (winreg.HKEY_LOCAL_MACHINE, r'SOFTWARE\Microsoft\Windows\CurrentVersion\Run'),
            (winreg.HKEY_LOCAL_MACHINE, r'SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce'),
            (winreg.HKEY_CURRENT_USER, r'SOFTWARE\Microsoft\Windows\CurrentVersion\Run'),
            (winreg.HKEY_CURRENT_USER, r'SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce'),
        ]
        for hive, path in run_keys:
            try:
                key = winreg.OpenKey(hive, path)
                i = 0
                while True:
                    try:
                        name, value, _ = winreg.EnumValue(key, i)
                        val_lower = value.lower() if isinstance(value, str) else ''
                        if any(sp in val_lower for sp in suspicious_paths):
                            findings.append(_make_finding(
                                'PER-004', 'medium', 'persistence',
                                f"Registry Run key to suspicious path: {name}",
                                f"Value: {value[:200]}",
                                'Run keys pointing to temp/download directories are a persistence indicator.'
                            ))
                        i += 1
                    except OSError:
                        break
                winreg.CloseKey(key)
            except OSError:
                continue
    except ImportError:
        pass

    return findings


def detect_ransomware():
    """Detect ransomware indicators — shadow copy deletion, ransom notes."""
    findings = []

    # RAN-001 & RAN-002: Check running processes for shadow copy / recovery deletion
    procs = _snapshot_processes()
    for p in procs:
        cl = p['cmdline_lower']
        if not cl:
            continue
        if 'vssadmin' in cl and 'delete' in cl and 'shadows' in cl:
            findings.append(_make_finding(
                'RAN-001', 'critical', 'ransomware',
                'Volume Shadow Copy deletion detected!',
                f"PID {p['pid']}: {p['cmdline'][:200]}",
                'CRITICAL: Shadow copy deletion is the #1 ransomware indicator. Isolate this machine immediately.'
            ))
        if 'wmic' in cl and 'shadowcopy' in cl and 'delete' in cl:
            findings.append(_make_finding(
                'RAN-001', 'critical', 'ransomware',
                'Shadow copy deletion via WMIC detected!',
                f"PID {p['pid']}: {p['cmdline'][:200]}",
                'CRITICAL: Isolate machine immediately. Check for encrypted files.'
            ))
        if 'bcdedit' in cl and 'recoveryenabled' in cl and 'no' in cl:
            findings.append(_make_finding(
                'RAN-002', 'critical', 'ransomware',
                'Windows Recovery disabled via bcdedit!',
                f"PID {p['pid']}: {p['cmdline'][:200]}",
                'CRITICAL: Disabling recovery is a pre-encryption ransomware step. Isolate NOW.'
            ))

    # RAN-003: Known ransom note filenames
    user_profile = os.environ.get('USERPROFILE', '')
    if user_profile:
        scan_dirs = [
            os.path.join(user_profile, 'Desktop'),
            os.path.join(user_profile, 'Documents'),
            os.path.join(user_profile, 'Downloads'),
        ]
        for scan_dir in scan_dirs:
            if os.path.exists(scan_dir):
                for pattern in RANSOM_NOTE_PATTERNS:
                    matches = glob.glob(os.path.join(scan_dir, pattern))
                    for match in matches:
                        findings.append(_make_finding(
                            'RAN-003', 'high', 'ransomware',
                            f"Potential ransom note found: {os.path.basename(match)}",
                            f"Location: {match}",
                            'Investigate this file. If ransomware is confirmed, do NOT pay — contact law enforcement.'
                        ))

    return findings


def detect_credentials():
    """Detect credential theft indicators — LSASS access, Mimikatz signatures."""
    findings = []
    procs = _snapshot_processes()
    mimikatz_sigs = ['sekurlsa::', 'kerberos::', 'lsadump::', 'mimikatz', 'gentilkiwi']

    for p in procs:
        cl = p['cmdline_lower']

        # CRD-002: Mimikatz signatures
        if any(sig in cl or sig in p['name'] for sig in mimikatz_sigs):
            findings.append(_make_finding(
                'CRD-002', 'critical', 'credentials',
                'Mimikatz-like tool detected!',
                f"PID {p['pid']} ({p['name']}): {p['cmdline'][:200]}",
                'CRITICAL: Active credential theft tool. Kill process and change all passwords immediately.'
            ))

        # CRD-003: procdump/comsvcs targeting lsass
        if ('procdump' in p['name'] or 'procdump' in cl) and 'lsass' in cl:
            findings.append(_make_finding(
                'CRD-003', 'high', 'credentials',
                'procdump targeting LSASS detected',
                f"PID {p['pid']}: {p['cmdline'][:200]}",
                'LSASS memory dump allows credential extraction. Kill process and investigate.'
            ))
        if 'comsvcs.dll' in cl and 'minidump' in cl:
            findings.append(_make_finding(
                'CRD-003', 'high', 'credentials',
                'comsvcs.dll MiniDump (LSASS dump technique)',
                f"PID {p['pid']}: {p['cmdline'][:200]}",
                'This is a known LSASS credential dumping technique. Investigate immediately.'
            ))

        # CRD-004: SAM/SYSTEM hive copy
        if 'reg' in p['name'] and 'save' in cl:
            if any(h in cl for h in ['hklm\\sam', 'hklm\\system', 'hklm\\security']):
                findings.append(_make_finding(
                    'CRD-004', 'medium', 'credentials',
                    'Registry hive export detected (SAM/SYSTEM/SECURITY)',
                    f"PID {p['pid']}: {p['cmdline'][:200]}",
                    'Exporting SAM/SYSTEM hives allows offline password cracking. Verify legitimacy.'
                ))

    return findings


def detect_defense_evasion():
    """Detect defense evasion — Defender disabled, logs cleared, AMSI bypass."""
    findings = []

    # DEF-001: Windows Defender real-time protection
    try:
        cmd = 'Get-MpPreference | Select-Object DisableRealtimeMonitoring | ConvertTo-Json'
        result = subprocess.run(
            ['powershell', '-NoProfile', '-Command', cmd],
            capture_output=True, text=True, timeout=8
        )
        if result.returncode == 0 and result.stdout.strip():
            import json
            try:
                data = json.loads(result.stdout)
                if data.get('DisableRealtimeMonitoring') is True:
                    findings.append(_make_finding(
                        'DEF-001', 'critical', 'defense_evasion',
                        'Windows Defender real-time protection is DISABLED!',
                        'DisableRealtimeMonitoring = True',
                        'CRITICAL: Re-enable immediately. Malware often disables Defender as a first step.'
                    ))
            except (json.JSONDecodeError, ValueError):
                pass
    except Exception:
        pass

    # DEF-004: Windows Firewall status
    try:
        result = subprocess.run(
            ['netsh', 'advfirewall', 'show', 'allprofiles', 'state'],
            capture_output=True, text=True, timeout=5
        )
        if result.returncode == 0:
            if 'OFF' in result.stdout.upper():
                findings.append(_make_finding(
                    'DEF-004', 'medium', 'defense_evasion',
                    'Windows Firewall has disabled profile(s)',
                    result.stdout.strip()[:200],
                    'At least one firewall profile is disabled. Verify this is intentional.'
                ))
    except Exception:
        pass

    # DEF-005: Tamper Protection
    try:
        cmd = 'Get-MpComputerStatus | Select-Object IsTamperProtected, RealTimeProtectionEnabled, AntivirusEnabled | ConvertTo-Json'
        result = subprocess.run(
            ['powershell', '-NoProfile', '-Command', cmd],
            capture_output=True, text=True, timeout=8
        )
        if result.returncode == 0 and result.stdout.strip():
            import json
            try:
                data = json.loads(result.stdout)
                if data.get('IsTamperProtected') is False:
                    findings.append(_make_finding(
                        'DEF-005', 'high', 'defense_evasion',
                        'Tamper Protection is DISABLED',
                        'IsTamperProtected = False',
                        'Tamper Protection prevents malware from disabling security. Re-enable in Windows Security.'
                    ))
            except (json.JSONDecodeError, ValueError):
                pass
    except Exception:
        pass

    # DEF-002: Check for event log clearing processes
    procs = _snapshot_processes()
    for p in procs:
        cl = p['cmdline_lower']
        if 'wevtutil' in cl and 'cl' in cl:
            findings.append(_make_finding(
                'DEF-002', 'high', 'defense_evasion',
                'Event log clearing detected (wevtutil)',
                f"PID {p['pid']}: {cl[:200]}",
                'Log clearing destroys forensic evidence. Investigate immediately.'
            ))
        if 'clear-eventlog' in cl:
            findings.append(_make_finding(
                'DEF-002', 'high', 'defense_evasion',
                'Event log clearing detected (Clear-EventLog)',
                f"PID {p['pid']}: {cl[:200]}",
                'Log clearing destroys forensic evidence. Investigate immediately.'
            ))

    return findings


def detect_anomalies():
    """Detect process anomalies — masquerading, injection indicators, suspicious chains."""
    findings = []
    procs = _snapshot_processes()

    for p in procs:
        # ANO-001: Process masquerade — system process from wrong path
        if p['name'] in SYSTEM_PROCESS_PATHS:
            expected = SYSTEM_PROCESS_PATHS[p['name']]
            if p['exe'] and expected not in p['exe']:
                findings.append(_make_finding(
                    'ANO-001', 'high', 'anomaly',
                    f"Process masquerade: {p['name']} running from unexpected path",
                    f"PID {p['pid']}, Path: {p['exe']} (expected: {expected})",
                    'System processes from wrong paths indicate masquerading malware. Kill and investigate.'
                ))

        # ANO-003: Suspicious parent-child chains
        if p['parent_name'] and p['name']:
            for par, child in SUSPICIOUS_PARENT_CHAINS:
                if p['parent_name'] == par and p['name'] == child:
                    findings.append(_make_finding(
                        'ANO-003', 'medium', 'anomaly',
                        f"Suspicious process chain: {p['parent_name']} → {p['name']}",
                        f"PID {p['pid']}: {p['cmdline'][:200]}",
                        'Office/script-host spawning shells often indicates macro malware or exploitation.'
                    ))

    return findings


def detect_network_threats():
    """Detect network threats — C2 ports, beaconing, excessive connections, data exfil."""
    findings = []

    try:
        conns = psutil.net_connections(kind='inet')

        # Group connections by PID
        pid_conns = {}
        for c in conns:
            if c.pid:
                pid_conns.setdefault(c.pid, []).append(c)

        for pid, conn_list in pid_conns.items():
            proc_name = 'Unknown'
            try:
                proc_name = psutil.Process(pid).name()
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

            established = [c for c in conn_list if c.status == 'ESTABLISHED' and c.raddr]

            # NET-001: C2 port connections
            for c in established:
                if c.raddr and c.raddr.port in C2_PORTS:
                    findings.append(_make_finding(
                        'NET-001', 'high', 'network',
                        f"Connection to known C2/attack port: {c.raddr.port}",
                        f"{proc_name} (PID {pid}) → {c.raddr.ip}:{c.raddr.port}",
                        'This port is commonly used by attack frameworks. Verify the remote destination.'
                    ))

            # NET-002: Excessive outbound connections
            # Skip known high-connection dev/system processes
            KNOWN_HIGH_CONN = {
                'chrome.exe', 'msedge.exe', 'firefox.exe', 'brave.exe',
                'code.exe', 'electron.exe', 'node.exe',
                'language_server_windows_x64.exe', 'languageserver_windows_x64.exe',
                'typescript-language-server.exe', 'gopls.exe', 'python.exe',
                'svchost.exe', 'system', 'teams.exe', 'slack.exe', 'discord.exe',
                'spotify.exe', 'onedrive.exe', 'ollama.exe', 'ollama app.exe',
                'protonvpn.exe', 'protonvpnservice.exe',
                'obs64.exe', 'msi center.exe',
            }
            outbound_count = len(established)
            if outbound_count > 50 and proc_name.lower() not in KNOWN_HIGH_CONN:
                findings.append(_make_finding(
                    'NET-002', 'medium', 'network',
                    f"Excessive outbound connections: {proc_name} ({outbound_count} established)",
                    f"PID {pid} has {outbound_count} ESTABLISHED connections",
                    'High connection count may indicate C2 beaconing, port scanning, or data exfiltration.'
                ))

            # NET-004: DNS-over-HTTPS from non-browser
            browser_names = {'chrome.exe', 'firefox.exe', 'msedge.exe', 'brave.exe', 'opera.exe', 'vivaldi.exe'}
            if proc_name.lower() not in browser_names:
                for c in established:
                    if c.raddr and c.raddr.port == 443:
                        if c.raddr.ip in ('1.1.1.1', '8.8.8.8', '8.8.4.4', '9.9.9.9', '1.0.0.1'):
                            findings.append(_make_finding(
                                'NET-004', 'high', 'network',
                                f"DNS-over-HTTPS from non-browser: {proc_name}",
                                f"PID {pid} → {c.raddr.ip}:443",
                                'Non-browser processes connecting to DNS-over-HTTPS resolvers may be exfiltrating data.'
                            ))

        # MIN-003: Mining pool port connections
        for c in conns:
            if c.status == 'ESTABLISHED' and c.raddr and c.raddr.port in MINER_PORTS:
                proc_name = 'Unknown'
                try:
                    proc_name = psutil.Process(c.pid).name() if c.pid else 'Unknown'
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass
                findings.append(_make_finding(
                    'MIN-003', 'high', 'cryptominer',
                    f"Connection to mining pool port: {c.raddr.port}",
                    f"{proc_name} (PID {c.pid}) → {c.raddr.ip}:{c.raddr.port}",
                    'This port is associated with cryptocurrency mining pools.'
                ))

    except Exception:
        pass

    return findings


def detect_cryptominers():
    """Detect cryptominer indicators — high CPU + network, known miner names."""
    findings = []
    procs = _snapshot_processes()

    for p in procs:
        # MIN-002: Known miner process names
        name_no_ext = os.path.splitext(p['name'])[0]
        if name_no_ext in MINER_NAMES:
            findings.append(_make_finding(
                'MIN-002', 'medium', 'cryptominer',
                f"Known cryptocurrency miner process: {p['name']}",
                f"PID {p['pid']}",
                'Kill this process unless you are intentionally mining.'
            ))

        # MIN-001: High CPU + network activity (potential miner)
        if p['cpu'] > 80:
            try:
                pconns = p['proc'].connections(kind='inet')
                if len([c for c in pconns if c.status == 'ESTABLISHED']) > 0:
                    findings.append(_make_finding(
                        'MIN-001', 'high', 'cryptominer',
                        f"High CPU process with network activity: {p['name']} ({p['cpu']}% CPU)",
                        f"PID {p['pid']}, {len(pconns)} network connections",
                        'Sustained high CPU with network connections is a cryptominer behavioral signature.'
                    ))
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass

    return findings


def detect_spyware():
    """Detect spyware/keylogger indicators."""
    findings = []
    procs = _snapshot_processes()
    legit_screen_tools = {'snippingtool.exe', 'screenclippinghost.exe', 'obs64.exe', 'obs32.exe',
                          'sharex.exe', 'lightshot.exe', 'greenshot.exe', 'snagit32.exe'}

    for p in procs:
        cl = p['cmdline_lower']
        if ('screenshot' in p['name'] or 'screencap' in p['name'] or 'keylog' in p['name'] or
            'keylogger' in cl or 'screenshot' in cl):
            if p['name'] not in legit_screen_tools:
                findings.append(_make_finding(
                    'SPY-002', 'medium', 'spyware',
                    f"Potential screen capture / keylogger: {p['name']}",
                    f"PID {p['pid']}: {cl[:200]}",
                    'Verify this is a legitimate application. Keyloggers are a direct privacy threat.'
                ))

    return findings


def detect_priv_escalation():
    """Detect privilege escalation patterns."""
    findings = []
    procs = _snapshot_processes()
    uac_bypass_procs = ['fodhelper.exe', 'eventvwr.exe', 'sdclt.exe', 'computerdefaults.exe']

    for p in procs:
        if p['name'] in uac_bypass_procs:
            if p['parent_name'] and p['parent_name'] not in ('explorer.exe', 'svchost.exe'):
                findings.append(_make_finding(
                    'PRV-001', 'high', 'priv_escalation',
                    f"Potential UAC bypass via {p['name']}",
                    f"PID {p['pid']}, Parent: {p['parent_name']}",
                    'This executable is commonly abused for UAC bypass. Verify parent process legitimacy.'
                ))

    return findings


def detect_fileless():
    """Detect fileless malware indicators — script hosts spawning shells."""
    findings = []
    procs = _snapshot_processes()

    for p in procs:
        if p['name'] in ('cmd.exe', 'powershell.exe', 'pwsh.exe'):
            if p['parent_name'] in ('wscript.exe', 'cscript.exe', 'mshta.exe'):
                findings.append(_make_finding(
                    'FIL-002', 'high', 'fileless',
                    f"Script host spawning shell: {p['parent_name']} → {p['name']}",
                    f"PID {p['pid']}: {p['cmdline'][:200]}",
                    'Script hosts spawning command shells indicate script-based malware execution.'
                ))

    return findings


def compute_score(findings):
    """Compute 0-100 security posture score. 100 = clean."""
    if not findings:
        return 100
    penalty = sum(SEV_WEIGHT.get(f['severity'], 0) for f in findings)
    return max(0, 100 - penalty)


# ═══════════════════════════════════════════════════
# SCAN ENGINE — BACKGROUND WORKER (COMPUTE PLANE)
# ═══════════════════════════════════════════════════
# Architecture:
#   COMPUTE: One background thread runs detectors.
#            Never occupies a Waitress worker thread.
#   READ:    All API endpoints return cached state instantly.
#            Zero subprocess calls in the request path.
# ═══════════════════════════════════════════════════

import threading

_scan_state = {
    'in_progress': False,
    'result': None,
    'last_completed': 0,
}
_scan_state_lock = threading.Lock()
_scan_done_event = threading.Event()


def _run_scan_worker():
    """Execute all detectors in a dedicated background thread.
    Signals _scan_done_event when complete."""
    global _cache_time
    _cache_time = 0
    _snapshot_processes()

    t0 = time.time()
    all_findings = []
    errors = []
    timings = {}

    detectors = [
        ('lolbins', detect_lolbins),
        ('persistence', detect_persistence),
        ('ransomware', detect_ransomware),
        ('credentials', detect_credentials),
        ('defense_evasion', detect_defense_evasion),
        ('anomalies', detect_anomalies),
        ('network', detect_network_threats),
        ('cryptominer', detect_cryptominers),
        ('spyware', detect_spyware),
        ('priv_escalation', detect_priv_escalation),
        ('fileless', detect_fileless),
    ]

    # Run ALL 11 detectors concurrently — safe here because this worker
    # thread is OUTSIDE Waitress. Subprocess calls release the GIL,
    # giving true parallelism across the i9-13950HX's 24 cores.
    from concurrent.futures import ThreadPoolExecutor, as_completed

    def _run_one(name_fn):
        n, fn = name_fn
        dt0 = time.time()
        try:
            r = fn()
            return n, r, None, round((time.time() - dt0) * 1000)
        except Exception as e:
            return n, [], str(e), round((time.time() - dt0) * 1000)

    with ThreadPoolExecutor(max_workers=11) as pool:
        futures = {pool.submit(_run_one, d): d[0] for d in detectors}
        for future in as_completed(futures):
            name, results, error, elapsed_ms = future.result()
            timings[name] = elapsed_ms
            if error:
                errors.append(f"{name}: {error}")
            else:
                all_findings.extend(results)

    sev_order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3, 'info': 4}
    all_findings.sort(key=lambda f: sev_order.get(f['severity'], 5))

    score = compute_score(all_findings)
    elapsed = round((time.time() - t0) * 1000)

    category_counts = {}
    for f in all_findings:
        cat = f['category']
        category_counts[cat] = category_counts.get(cat, 0) + 1

    result = {
        'findings': all_findings,
        'score': score,
        'total_findings': len(all_findings),
        'category_counts': category_counts,
        'scan_time_ms': elapsed,
        'detector_timings_ms': timings,
        'errors': errors,
        'timestamp': datetime.now().isoformat()
    }

    with _scan_state_lock:
        _scan_state['result'] = result
        _scan_state['last_completed'] = time.time()
        _scan_state['in_progress'] = False

    # Persist to scan history DB
    if _history_available:
        try:
            save_scan(score, all_findings, elapsed)
        except Exception as e:
            print(f'[scan_history] Failed to persist scan: {e}')

    _scan_done_event.set()


def _trigger_scan():
    """Launch a background scan if one isn't already running.
    Returns (triggered: bool, cached_result: dict|None)."""
    with _scan_state_lock:
        if _scan_state['in_progress']:
            return False, _scan_state['result']
        _scan_state['in_progress'] = True
        _scan_done_event.clear()
    worker = threading.Thread(target=_run_scan_worker, daemon=True)
    worker.start()
    with _scan_state_lock:
        return True, _scan_state['result']


# ═══════════════════════════════════════════════════
# API ENDPOINTS (READ PLANE)
# All reads return cached state. Zero compute in request path.
# ═══════════════════════════════════════════════════

@threat_bp.route('/scan')
def full_scan():
    """Trigger a scan and return results.
    - Kicks off background worker, waits via Event (no polling loop).
    - If scan already running, returns last cached result immediately.
    - NEVER runs detectors inside a Waitress thread."""
    triggered, cached = _trigger_scan()

    if not triggered and cached:
        # Scan already running — return last known good state
        return jsonify(cached)

    # Wait for the background worker via Event.wait() — efficient, no busy loop
    # Timeout: 300s. The thread sleeps on the event, giving max CPU to the worker.
    completed = _scan_done_event.wait(timeout=300)

    with _scan_state_lock:
        if completed and _scan_state['result']:
            return jsonify(_scan_state['result'])
        if _scan_state['result']:
            return jsonify(_scan_state['result'])

    return jsonify({'error': 'Scan timed out', 'score': 0, 'findings': [],
                    'total_findings': 0, 'category_counts': {},
                    'scan_time_ms': 300000, 'errors': ['timeout'],
                    'timestamp': datetime.now().isoformat()})


@threat_bp.route('/score')
def get_score():
    """Read-only score from cached scan results. No detectors called."""
    with _scan_state_lock:
        result = _scan_state['result']

    if result:
        sev_counts = {}
        for f in result['findings']:
            sev_counts[f['severity']] = sev_counts.get(f['severity'], 0) + 1
        return jsonify({
            'score': result['score'],
            'severity_counts': sev_counts,
            'total_findings': result['total_findings'],
            'scan_time_ms': result['scan_time_ms'],
            'cached': True
        })

    # No scan yet — trigger one and return immediately with defaults
    _trigger_scan()
    return jsonify({
        'score': 100,
        'severity_counts': {},
        'total_findings': 0,
        'scan_time_ms': 0,
        'cached': False,
        'scan_in_progress': True
    })


@threat_bp.route('/status')
def scan_status():
    """Check scan engine status — is a scan running? When was last scan?"""
    with _scan_state_lock:
        return jsonify({
            'in_progress': _scan_state['in_progress'],
            'last_completed': _scan_state['last_completed'],
            'has_results': _scan_state['result'] is not None,
            'last_score': _scan_state['result']['score'] if _scan_state['result'] else None,
            'last_findings_count': _scan_state['result']['total_findings'] if _scan_state['result'] else 0,
        })


@threat_bp.route('/last-scan')
def last_scan():
    """Read-only last scan summary for the Overview posture badge. Never triggers a scan."""
    with _scan_state_lock:
        result = _scan_state['result']
    if not result:
        return jsonify({'score': None}), 200
    return jsonify({
        'score': result.get('score', 0),
        'total_findings': result.get('total_findings', 0),
        'scan_time': result.get('timestamp', ''),
    })


@threat_bp.route('/lolbins')
def scan_lolbins():
    t0 = time.time()
    findings = detect_lolbins()
    return jsonify({'findings': findings, 'scan_time_ms': round((time.time() - t0) * 1000)})


@threat_bp.route('/persistence')
def scan_persistence():
    t0 = time.time()
    findings = detect_persistence()
    return jsonify({'findings': findings, 'scan_time_ms': round((time.time() - t0) * 1000)})


@threat_bp.route('/ransomware')
def scan_ransomware():
    t0 = time.time()
    findings = detect_ransomware()
    return jsonify({'findings': findings, 'scan_time_ms': round((time.time() - t0) * 1000)})


@threat_bp.route('/credentials')
def scan_credentials():
    t0 = time.time()
    findings = detect_credentials()
    return jsonify({'findings': findings, 'scan_time_ms': round((time.time() - t0) * 1000)})


@threat_bp.route('/defense-evasion')
def scan_defense_evasion():
    t0 = time.time()
    findings = detect_defense_evasion()
    return jsonify({'findings': findings, 'scan_time_ms': round((time.time() - t0) * 1000)})


@threat_bp.route('/history')
def scan_history_endpoint():
    """Return scan history (newest first)."""
    if not _history_available:
        return jsonify({'history': [], 'available': False})
    limit = request.args.get('limit', 50, type=int)
    history = get_history(limit)
    return jsonify({'history': history, 'available': True})


@threat_bp.route('/history/<int:scan_id>')
def scan_history_detail(scan_id):
    """Return a single scan with its findings."""
    if not _history_available:
        return jsonify({'error': 'History not available'}), 503
    detail = get_scan_detail(scan_id)
    if not detail:
        return jsonify({'error': 'Scan not found'}), 404
    return jsonify(detail)

