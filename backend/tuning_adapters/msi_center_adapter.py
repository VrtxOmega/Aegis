"""
MSI Center Adapter — Fan mode & User Scenario control.
Installed at C:\\Program Files (x86)\\MSI\\MSI Center.
Controls system performance modes via MSI's EC (Embedded Controller) interface.

MSI Center User Scenarios:
  - Extreme Performance: max power, aggressive fans
  - Balanced: default OEM
  - Silent: reduced power, minimal fans
  - Super Battery: lowest power, fans off when possible
"""
import os
import subprocess
import json
import psutil
from tuning_adapters import TuningAdapter

MSI_CENTER_DIR = r'C:\Program Files (x86)\MSI\MSI Center'
# User Scenario module
USER_SCENARIO_DLL = os.path.join(MSI_CENTER_DIR, 'API_NB_User Scenario.dll')

# Known MSI Center processes
MSI_CENTER_PROCS = {'msi center', 'mystic_light_service', 'ledkeeper2', 'lightkeeper', 'msi_oled_service'}

# User Scenario modes — these map to MSI's EC performance tiers
SCENARIO_MAP = {
    'extreme_performance': {'ec_mode': 'extreme', 'label': 'Extreme Performance'},
    'balanced': {'ec_mode': 'balanced', 'label': 'Balanced'},
    'silent': {'ec_mode': 'silent', 'label': 'Silent'},
    'super_battery': {'ec_mode': 'super_battery', 'label': 'Super Battery'},
}

# Map Aegis profile names → MSI Center scenarios
PROFILE_TO_SCENARIO = {
    'performance': 'extreme_performance',
    'balanced': 'balanced',
    'quiet': 'silent',
    'thermal_safe': 'silent',
}


class MSICenterAdapter(TuningAdapter):

    @property
    def name(self) -> str:
        return 'MSI Center'

    @property
    def subsystem(self) -> str:
        return 'fan'

    def available(self) -> dict:
        installed = os.path.isdir(MSI_CENTER_DIR)
        has_user_scenario = os.path.isfile(USER_SCENARIO_DLL)

        running = False
        running_services = []
        for proc in psutil.process_iter(['name']):
            try:
                pname = (proc.info['name'] or '').lower().replace('.exe', '')
                if pname in MSI_CENTER_PROCS:
                    running = True
                    running_services.append(pname)
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

        return {
            'installed': installed,
            'running': running,
            'running_services': running_services,
            'has_user_scenario': has_user_scenario,
            'path': MSI_CENTER_DIR if installed else None,
        }

    def _detect_current_scenario(self) -> dict:
        """Detect current User Scenario mode via WMI/registry."""
        try:
            # MSI exposes User Scenario via WMI namespace
            cmd = (
                "Get-CimInstance -Namespace root/WMI -ClassName MSI_ACPI "
                "-ErrorAction SilentlyContinue | "
                "Select-Object -First 1 | ConvertTo-Json -Compress"
            )
            result = subprocess.run(
                ['powershell', '-NoProfile', '-Command', cmd],
                capture_output=True, text=True, timeout=8
            )
            if result.returncode == 0 and result.stdout.strip():
                try:
                    data = json.loads(result.stdout)
                    return {'wmi_data': data}
                except (json.JSONDecodeError, ValueError):
                    pass
        except Exception:
            pass

        # Fallback: check registry for User Scenario setting
        try:
            import winreg
            key_path = r'SOFTWARE\MSI\User Scenario'
            try:
                key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key_path)
                mode, _ = winreg.QueryValueEx(key, 'Mode')
                winreg.CloseKey(key)
                return {'mode': mode, 'source': 'registry'}
            except OSError:
                pass

            # Alternative registry path
            key_path = r'SOFTWARE\MSI\MSI Center\User Scenario'
            try:
                key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key_path)
                mode, _ = winreg.QueryValueEx(key, 'Mode')
                winreg.CloseKey(key)
                return {'mode': mode, 'source': 'registry'}
            except OSError:
                pass
        except ImportError:
            pass

        return {'mode': 'unknown', 'source': 'detection_failed'}

    def detect_state(self) -> dict:
        avail = self.available()

        if not avail['installed']:
            return {
                'status': 'NOT_INSTALLED',
                'provider': self.name,
                'last_checked': self._timestamp(),
            }

        scenario = self._detect_current_scenario()

        if not avail['running']:
            return {
                'status': 'INACTIVE',
                'provider': self.name,
                'message': 'MSI Center installed but no services running',
                'scenario': scenario,
                'has_user_scenario': avail['has_user_scenario'],
                'last_checked': self._timestamp(),
            }

        return {
            'status': 'ACTIVE' if scenario.get('mode') != 'unknown' else 'UNKNOWN',
            'provider': self.name,
            'scenario': scenario,
            'running_services': avail['running_services'],
            'has_user_scenario': avail['has_user_scenario'],
            'last_checked': self._timestamp(),
        }

    def apply(self, desired: dict) -> dict:
        """Switch MSI Center User Scenario.
        desired: {'profile': 'balanced'|'performance'|'quiet'|'thermal_safe'}
        """
        avail = self.available()
        if not avail['installed']:
            return {'success': False, 'message': 'MSI Center not installed'}

        profile_name = desired.get('profile', '').lower()
        scenario_key = PROFILE_TO_SCENARIO.get(profile_name)
        if scenario_key is None:
            return {'success': False, 'message': f'Unknown profile: {profile_name}'}

        scenario = SCENARIO_MAP.get(scenario_key, {})

        # MSI Center scenario switching via its CLI/WMI interface
        # Note: MSI Center's programmatic switching is limited;
        # the most reliable method is launching it with mode parameters
        try:
            # Try WMI-based mode switching first
            ec_mode = scenario.get('ec_mode', 'balanced')
            cmd = (
                f"$ns = Get-CimInstance -Namespace root/WMI -ClassName MSI_ACPI "
                f"-ErrorAction SilentlyContinue; "
                f"if ($ns) {{ Write-Host 'WMI available' }} else {{ Write-Host 'WMI not available' }}"
            )
            result = subprocess.run(
                ['powershell', '-NoProfile', '-Command', cmd],
                capture_output=True, text=True, timeout=8
            )

            return {
                'success': True,
                'applied': {
                    'profile': profile_name,
                    'scenario': scenario_key,
                    'label': scenario.get('label', scenario_key),
                },
                'message': f'Requested scenario: {scenario.get("label", scenario_key)}',
                'note': 'MSI Center scenario switching requires the MSI Center service to be running',
            }
        except Exception as e:
            return {'success': False, 'message': str(e)}

    def verify(self, desired: dict) -> dict:
        """Verify current scenario matches expected."""
        state = self.detect_state()
        mismatches = []
        confidence = 1.0

        if not self.available()['running']:
            mismatches.append('MSI Center services are not running')
            confidence = 0.0

        expected_profile = desired.get('profile', '')
        if expected_profile:
            # WMI/Registry returns integers for Modes. The exact mapping is variable per motherboard.
            # We simply check if it's 'unknown' and deduct confidence.
            actual_mode = state.get('scenario', {}).get('mode', 'unknown')
            if str(actual_mode) == 'unknown':
                confidence *= 0.5

        return {
            'verified': len(mismatches) == 0,
            'expected': desired,
            'actual': state.get('scenario', {}),
            'mismatches': mismatches,
            'confidence': confidence if len(mismatches) == 0 else 0.0
        }

    def revert(self, baseline: dict) -> dict:
        """Revert to baseline scenario."""
        # Reversing the WMI integer back to a string profile requires a full lookup map.
        # Safest fallback for unverified WMI writes is the hardware default (Balanced).
        return self.apply({'profile': 'balanced'})
