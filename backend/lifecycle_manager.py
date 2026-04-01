"""
Aegis — Dependency Auto-Lifecycle Manager
==========================================
Manages external tool lifecycle so the user never has to manually
pre-launch companion apps.

Rules:
  Ollama:        auto-start when AI is needed, NEVER auto-stop (user uses it externally)
  ThrottleStop:  auto-start on tuning apply, auto-stop on profile deactivate/revert
  Afterburner:   auto-start on tuning apply, auto-stop on profile deactivate/revert

Thread-safe. All operations are idempotent.
"""
import os
import time
import subprocess
import threading
import requests
import psutil
from datetime import datetime

# ═══════════════════════════════════════════
# MANAGED APP REGISTRY
# ═══════════════════════════════════════════

MANAGED_APPS = {
    'ollama': {
        'exe': 'ollama',
        'args': ['serve'],
        'health_url': 'http://127.0.0.1:11434/api/version',
        'health_timeout': 3,
        'startup_wait_s': 10,
        'process_names': ['ollama', 'ollama app'],
        'auto_stop': False,      # NEVER auto-stop — user uses it externally
        'description': 'AI Engine (Ollama)',
    },
    'throttlestop': {
        'exe': r'C:\ThrottleStop\ThrottleStop.exe',
        'args': [],
        'health_url': None,      # No HTTP endpoint — detect via process
        'startup_wait_s': 5,
        'process_names': ['throttlestop'],
        'auto_stop': True,       # Stop when tuning profiles are deactivated
        'description': 'CPU Tuning (ThrottleStop)',
    },
    'afterburner': {
        'exe': r'C:\Program Files (x86)\MSI Afterburner\MSIAfterburner.exe',
        'args': [],
        'health_url': None,
        'startup_wait_s': 5,
        'process_names': ['msiafterburner'],
        'auto_stop': True,       # Stop when tuning profiles are deactivated
        'description': 'GPU Tuning (MSI Afterburner)',
    },
}


class LifecycleManager:
    """Manages start/stop/detect for external dependencies."""

    def __init__(self):
        self._lock = threading.Lock()
        self._managed_processes = {}  # app_name -> subprocess.Popen
        self._start_times = {}        # app_name -> datetime

    # ═══════════════════════════════════════
    # DETECTION
    # ═══════════════════════════════════════

    def is_installed(self, app_name: str) -> bool:
        """Check if the app executable exists on disk."""
        config = MANAGED_APPS.get(app_name)
        if not config:
            return False
        exe = config['exe']
        # For 'ollama' (no path), check if it's on PATH
        if not os.path.sep in exe:
            import shutil
            return shutil.which(exe) is not None
        return os.path.isfile(exe)

    def is_running(self, app_name: str) -> bool:
        """Check if any process matching the app's known names is alive."""
        config = MANAGED_APPS.get(app_name)
        if not config:
            return False
        target_names = [n.lower() for n in config['process_names']]
        for proc in psutil.process_iter(['name']):
            try:
                pname = (proc.info['name'] or '').lower()
                if any(t in pname for t in target_names):
                    return True
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        return False

    def is_healthy(self, app_name: str) -> bool:
        """For apps with a health URL, verify they're responding."""
        config = MANAGED_APPS.get(app_name)
        if not config or not config.get('health_url'):
            return self.is_running(app_name)
        try:
            r = requests.get(
                config['health_url'],
                timeout=config.get('health_timeout', 3)
            )
            return r.status_code == 200
        except Exception:
            return False

    def get_memory_mb(self, app_name: str) -> float:
        """Get total memory usage across all processes for this app."""
        config = MANAGED_APPS.get(app_name)
        if not config:
            return 0
        target_names = [n.lower() for n in config['process_names']]
        total = 0
        for proc in psutil.process_iter(['name', 'memory_info']):
            try:
                pname = (proc.info['name'] or '').lower()
                if any(t in pname for t in target_names):
                    total += proc.info['memory_info'].rss
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        return round(total / (1024 * 1024), 1)

    # ═══════════════════════════════════════
    # START
    # ═══════════════════════════════════════

    def ensure_running(self, app_name: str) -> dict:
        """Ensure an app is running. Start it if not. Idempotent.
        Returns: {'running': bool, 'started': bool, 'message': str}
        """
        config = MANAGED_APPS.get(app_name)
        if not config:
            return {'running': False, 'started': False,
                    'message': f'Unknown app: {app_name}'}

        # Already running? Nothing to do.
        if self.is_running(app_name):
            return {'running': True, 'started': False,
                    'message': f'{config["description"]} is already running'}

        # Not installed?
        if not self.is_installed(app_name):
            return {'running': False, 'started': False,
                    'message': f'{config["description"]} is not installed'}

        # Start it
        with self._lock:
            # Double-check after acquiring lock
            if self.is_running(app_name):
                return {'running': True, 'started': False,
                        'message': f'{config["description"]} started by another thread'}

            try:
                exe = config['exe']
                args = config.get('args', [])

                # For apps on PATH (like ollama), use shell resolution
                if not os.path.sep in exe:
                    proc = subprocess.Popen(
                        [exe] + args,
                        stdout=subprocess.DEVNULL,
                        stderr=subprocess.DEVNULL,
                        creationflags=subprocess.DETACHED_PROCESS
                            | subprocess.CREATE_NO_WINDOW
                    )
                else:
                    proc = subprocess.Popen(
                        [exe] + args,
                        stdout=subprocess.DEVNULL,
                        stderr=subprocess.DEVNULL,
                        cwd=os.path.dirname(exe),
                        creationflags=subprocess.DETACHED_PROCESS
                            | subprocess.CREATE_NO_WINDOW
                    )

                self._managed_processes[app_name] = proc
                self._start_times[app_name] = datetime.now()

            except Exception as e:
                return {'running': False, 'started': False,
                        'message': f'Failed to start {config["description"]}: {e}'}

        # Wait for it to come up
        wait_s = config.get('startup_wait_s', 10)
        deadline = time.time() + wait_s
        while time.time() < deadline:
            if config.get('health_url'):
                if self.is_healthy(app_name):
                    return {'running': True, 'started': True,
                            'message': f'{config["description"]} started and healthy'}
            else:
                if self.is_running(app_name):
                    return {'running': True, 'started': True,
                            'message': f'{config["description"]} started'}
            time.sleep(0.5)

        # Timed out
        running = self.is_running(app_name)
        return {
            'running': running,
            'started': running,
            'message': f'{config["description"]} {"started (slow)" if running else "failed to start"}'
        }

    # ═══════════════════════════════════════
    # STOP
    # ═══════════════════════════════════════

    def stop(self, app_name: str) -> dict:
        """Stop an app. Only works for apps with auto_stop=True.
        Returns: {'stopped': bool, 'message': str}
        """
        config = MANAGED_APPS.get(app_name)
        if not config:
            return {'stopped': False, 'message': f'Unknown app: {app_name}'}

        if not config.get('auto_stop', False):
            return {'stopped': False,
                    'message': f'{config["description"]} is not auto-stoppable'}

        if not self.is_running(app_name):
            return {'stopped': True,
                    'message': f'{config["description"]} is already stopped'}

        with self._lock:
            target_names = [n.lower() for n in config['process_names']]
            killed = 0
            for proc in psutil.process_iter(['name', 'pid']):
                try:
                    pname = (proc.info['name'] or '').lower()
                    if any(t in pname for t in target_names):
                        proc.terminate()
                        killed += 1
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue

            # Clean up tracked references
            self._managed_processes.pop(app_name, None)
            self._start_times.pop(app_name, None)

        if killed > 0:
            # Wait briefly for termination
            time.sleep(2)
            return {'stopped': True,
                    'message': f'{config["description"]} stopped ({killed} processes)'}
        return {'stopped': False,
                'message': f'Could not find {config["description"]} processes to stop'}

    # ═══════════════════════════════════════
    # STATUS (for UI)
    # ═══════════════════════════════════════

    def get_all_status(self) -> dict:
        """Return status of all managed dependencies for the UI."""
        status = {}
        for app_name, config in MANAGED_APPS.items():
            installed = self.is_installed(app_name)
            running = self.is_running(app_name) if installed else False
            healthy = self.is_healthy(app_name) if running else False
            mem = self.get_memory_mb(app_name) if running else 0

            status[app_name] = {
                'name': config['description'],
                'installed': installed,
                'running': running,
                'healthy': healthy,
                'memory_mb': mem,
                'auto_stop': config.get('auto_stop', False),
                'started_at': self._start_times.get(app_name, '').isoformat()
                    if app_name in self._start_times else None,
            }

        # Add passive dependencies (not managed, just detected)
        # Proton VPN
        vpn_running = False
        for proc in psutil.process_iter(['name']):
            try:
                pname = (proc.info['name'] or '').lower()
                if 'protonvpn' in pname:
                    vpn_running = True
                    break
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        status['protonvpn'] = {
            'name': 'Proton VPN',
            'installed': True,
            'running': vpn_running,
            'healthy': vpn_running,
            'memory_mb': 0,  # Don't bother counting — it's a system service
            'auto_stop': False,
            'managed': False,
            'note': 'System service (auto-starts)',
        }

        # MSI Center
        msi_running = False
        for proc in psutil.process_iter(['name']):
            try:
                pname = (proc.info['name'] or '').lower()
                if 'msi.centralserver' in pname or 'msi_central' in pname:
                    msi_running = True
                    break
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        status['msicenter'] = {
            'name': 'MSI Center',
            'installed': True,
            'running': msi_running,
            'healthy': msi_running,
            'memory_mb': 0,
            'auto_stop': False,
            'managed': False,
            'note': 'System service (auto-starts)',
        }

        return status


# ═══════════════════════════════════════════
# SINGLETON
# ═══════════════════════════════════════════
_instance = None


def get_lifecycle_manager() -> LifecycleManager:
    global _instance
    if _instance is None:
        _instance = LifecycleManager()
    return _instance
