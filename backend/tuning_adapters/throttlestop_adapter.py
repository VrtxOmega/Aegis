"""
ThrottleStop Adapter — CPU voltage offset & power limit control.
Portable tool at C:\\ThrottleStop\\ThrottleStop.exe.
Reads ThrottleStop.ini for config state, switches between pre-saved profiles.
"""
import os
import configparser
import subprocess
import psutil
from tuning_adapters import TuningAdapter

THROTTLESTOP_DIR = r'C:\ThrottleStop'
THROTTLESTOP_EXE = os.path.join(THROTTLESTOP_DIR, 'ThrottleStop.exe')
THROTTLESTOP_INI = os.path.join(THROTTLESTOP_DIR, 'ThrottleStop.ini')

# Profile names mapped to TS profile indices (1-4)
# Matches the user's actual ThrottleStop dot order (left to right)
PROFILE_MAP = {
    'balanced': 1,
    'performance': 2,
    'quiet': 3,
    'thermal_safe': 4,
}


class ThrottleStopAdapter(TuningAdapter):

    @property
    def name(self) -> str:
        return 'ThrottleStop'

    @property
    def subsystem(self) -> str:
        return 'cpu'

    def available(self) -> dict:
        installed = os.path.isfile(THROTTLESTOP_EXE)
        running = False
        if installed:
            for proc in psutil.process_iter(['name']):
                try:
                    if proc.info['name'] and 'throttlestop' in proc.info['name'].lower():
                        running = True
                        break
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue

        return {
            'installed': installed,
            'running': running,
            'path': THROTTLESTOP_EXE if installed else None,
            'version': '9.7' if installed else None,
            'ini_exists': os.path.isfile(THROTTLESTOP_INI) if installed else False,
        }

    def _read_ini(self) -> dict:
        """Parse ThrottleStop.ini for current profile and voltage settings."""
        if not os.path.isfile(THROTTLESTOP_INI):
            return {'error': 'ThrottleStop.ini not found'}

        try:
            config = configparser.ConfigParser()
            config.read(THROTTLESTOP_INI)

            result = {}
            # ThrottleStop uses numbered sections for profiles
            if config.has_section('ThrottleStop'):
                result['current_profile'] = config.get('ThrottleStop', 'CurrentProfile', fallback='0')

            # Read FIVR (voltage) settings if available
            for section in config.sections():
                if 'FIVR' in section or 'Voltage' in section:
                    result[section] = dict(config[section])

            return result
        except Exception as e:
            return {'error': str(e)}

    def detect_state(self) -> dict:
        avail = self.available()
        if not avail['installed']:
            return {
                'status': 'NOT_INSTALLED',
                'provider': self.name,
                'message': 'ThrottleStop not found at C:\\ThrottleStop',
                'last_checked': self._timestamp(),
            }

        if not avail['running']:
            return {
                'status': 'INACTIVE',
                'provider': self.name,
                'message': 'ThrottleStop installed but not running',
                'ini_state': self._read_ini() if avail.get('ini_exists') else {},
                'last_checked': self._timestamp(),
            }

        ini_state = self._read_ini() if avail.get('ini_exists') else {}

        # Get live CPU telemetry for verification
        cpu_state = {}
        try:
            freq = psutil.cpu_freq()
            if freq:
                cpu_state['current_mhz'] = round(freq.current)
                cpu_state['max_mhz'] = round(freq.max)
            cpu_state['percent'] = psutil.cpu_percent(interval=0.1)
        except Exception:
            pass

        return {
            'status': 'ACTIVE',
            'provider': self.name,
            'ini_state': ini_state,
            'cpu_telemetry': cpu_state,
            'last_checked': self._timestamp(),
        }

    def apply(self, desired: dict) -> dict:
        """Switch ThrottleStop to a named profile.
        desired: {'profile': 'balanced'|'performance'|'quiet'|'thermal_safe'}
        ThrottleStop CLI: ThrottleStop.exe -pN (where N=1-4)
        """
        avail = self.available()
        if not avail['installed']:
            return {'success': False, 'message': 'ThrottleStop not installed'}

        profile_name = desired.get('profile', '').lower()
        profile_idx = PROFILE_MAP.get(profile_name)
        if profile_idx is None:
            return {'success': False, 'message': f'Unknown profile: {profile_name}'}

        try:
            # ThrottleStop CLI accepts -p1 through -p4 for profile switching
            cmd = [THROTTLESTOP_EXE, f'-p{profile_idx}']
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            return {
                'success': True,
                'applied': {'profile': profile_name, 'index': profile_idx},
                'message': f'Switched to profile {profile_name} (slot {profile_idx})',
            }
        except subprocess.TimeoutExpired:
            return {'success': False, 'message': 'ThrottleStop profile switch timed out'}
        except Exception as e:
            return {'success': False, 'message': str(e)}

    def verify(self, desired: dict) -> dict:
        """Verify CPU telemetry aligns with the expected profile behavior."""
        state = self.detect_state()
        mismatches = []
        confidence = 1.0

        # Basic verification: is ThrottleStop still running?
        avail = self.available()
        if not avail['running']:
            mismatches.append('ThrottleStop is not running')
            confidence = 0.0
            
        # Extract applied profile index via ini if possible
        expected_profile = desired.get('profile', '')
        if expected_profile:
            expected_idx = str(PROFILE_MAP.get(expected_profile.lower(), 1))
            actual_idx = state.get('ini_state', {}).get('current_profile', '0')
            if actual_idx != '0' and str(expected_idx) != str(actual_idx):
                mismatches.append(f'Profile mismatch: expected slot {expected_idx}, found {actual_idx}')
                confidence *= 0.5

        return {
            'verified': len(mismatches) == 0,
            'expected': desired,
            'actual': state,
            'mismatches': mismatches,
            'confidence': confidence if len(mismatches) == 0 else 0.0
        }

    def revert(self, baseline: dict) -> dict:
        """Revert to baseline by switching to the saved profile."""
        # Baseline is the output of detect_state()
        ini_state = baseline.get('ini_state', {})
        current_profile_idx = ini_state.get('current_profile', '1')
        
        # Reverse lookup profile name from index
        profile_name = 'balanced'
        for name, idx in PROFILE_MAP.items():
            if str(idx) == str(current_profile_idx):
                profile_name = name
                break
                
        return self.apply({'profile': profile_name})
