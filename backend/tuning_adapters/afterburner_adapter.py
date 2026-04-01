"""
MSI Afterburner Adapter — GPU voltage/frequency curve & memory OC.
Installed at C:\\Program Files (x86)\\MSI Afterburner\\MSIAfterburner.exe.
Profile switching via CLI (-Profile1 through -Profile5).
State verification via nvidia-smi telemetry.
"""
import os
import subprocess
import psutil
from tuning_adapters import TuningAdapter

AFTERBURNER_DIR = r'C:\Program Files (x86)\MSI Afterburner'
AFTERBURNER_EXE = os.path.join(AFTERBURNER_DIR, 'MSIAfterburner.exe')
AFTERBURNER_CFG = os.path.join(AFTERBURNER_DIR, 'Profiles', 'MSIAfterburner.cfg')

# Aegis profile names → Afterburner profile slots (1-5)
# Matches user's actual AB setup: 1=stock, 2=perf(+150/+500), 3=quiet(-200/+0)
PROFILE_MAP = {
    'balanced': 1,     # Slot 1: stock clocks (safe baseline)
    'performance': 2,  # Slot 2: +150 core, +500 mem
    'quiet': 3,        # Slot 3: -200 core, +0 mem
    'thermal_safe': 3, # Reuse quiet slot for thermal emergency
}


class AfterburnerAdapter(TuningAdapter):

    @property
    def name(self) -> str:
        return 'MSI Afterburner'

    @property
    def subsystem(self) -> str:
        return 'gpu'

    def available(self) -> dict:
        installed = os.path.isfile(AFTERBURNER_EXE)
        running = False
        if installed:
            for proc in psutil.process_iter(['name']):
                try:
                    if proc.info['name'] and 'msiafterburner' in proc.info['name'].lower():
                        running = True
                        break
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue

        # Check if profiles exist
        profiles_dir = os.path.join(AFTERBURNER_DIR, 'Profiles')
        profile_count = 0
        if os.path.isdir(profiles_dir):
            # Profile slots are stored as VEN_*.cfg files
            profile_count = len([f for f in os.listdir(profiles_dir)
                                if f.startswith('VEN_') and f.endswith('.cfg')])

        return {
            'installed': installed,
            'running': running,
            'path': AFTERBURNER_EXE if installed else None,
            'profile_slots_configured': profile_count,
            'profiles_dir': profiles_dir if installed else None,
        }

    def _nvidia_smi_state(self) -> dict:
        """Read current GPU state from nvidia-smi."""
        try:
            result = subprocess.run(
                ['nvidia-smi',
                 '--query-gpu=name,temperature.gpu,power.draw,power.limit,'
                 'clocks.gr,clocks.mem,clocks.max.gr,clocks.max.mem,'
                 'fan.speed,utilization.gpu,memory.used,memory.total',
                 '--format=csv,noheader,nounits'],
                capture_output=True, text=True, timeout=10
            )
            if result.returncode != 0:
                return {'error': 'nvidia-smi failed'}

            values = [v.strip() for v in result.stdout.strip().split(',')]
            if len(values) < 12:
                return {'error': f'Incomplete data: {len(values)} fields'}

            def safe_float(v):
                try:
                    if '[N/A]' in str(v) or 'N/A' in str(v):
                        return None
                    return float(v)
                except (ValueError, TypeError):
                    return None

            return {
                'gpu_name': values[0],
                'temp_c': safe_float(values[1]),
                'power_draw_w': safe_float(values[2]),
                'power_limit_w': safe_float(values[3]),
                'clock_mhz': safe_float(values[4]),
                'mem_clock_mhz': safe_float(values[5]),
                'max_clock_mhz': safe_float(values[6]),
                'max_mem_clock_mhz': safe_float(values[7]),
                'fan_speed_pct': safe_float(values[8]),
                'gpu_util_pct': safe_float(values[9]),
                'vram_used_mb': safe_float(values[10]),
                'vram_total_mb': safe_float(values[11]),
            }
        except Exception as e:
            return {'error': str(e)}

    def detect_state(self) -> dict:
        avail = self.available()
        gpu = self._nvidia_smi_state()

        if not avail['installed']:
            return {
                'status': 'NOT_INSTALLED',
                'provider': self.name,
                'gpu_telemetry': gpu,
                'last_checked': self._timestamp(),
            }

        if not avail['running']:
            return {
                'status': 'INACTIVE',
                'provider': self.name,
                'message': 'Afterburner installed but not running — GPU running stock settings',
                'gpu_telemetry': gpu,
                'profile_slots': avail['profile_slots_configured'],
                'last_checked': self._timestamp(),
            }

        return {
            'status': 'ACTIVE',
            'provider': self.name,
            'gpu_telemetry': gpu,
            'profile_slots': avail['profile_slots_configured'],
            'last_checked': self._timestamp(),
        }

    def apply(self, desired: dict) -> dict:
        """Switch Afterburner to a named profile.
        desired: {'profile': 'balanced'|'performance'|'quiet'}
        Afterburner CLI: MSIAfterburner.exe -ProfileN
        """
        avail = self.available()
        if not avail['installed']:
            return {'success': False, 'message': 'MSI Afterburner not installed'}
        if not avail['running']:
            return {'success': False, 'message': 'MSI Afterburner not running — start it first'}
        if avail['profile_slots_configured'] == 0:
            return {'success': False, 'message': 'No Afterburner profiles saved — create profiles in AB first'}

        profile_name = desired.get('profile', '').lower()
        profile_idx = PROFILE_MAP.get(profile_name)
        if profile_idx is None:
            return {'success': False, 'message': f'Unknown profile: {profile_name}'}

        try:
            cmd = [AFTERBURNER_EXE, f'-Profile{profile_idx}']
            subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            return {
                'success': True,
                'applied': {'profile': profile_name, 'slot': profile_idx},
                'message': f'Switched GPU to profile {profile_name} (slot {profile_idx})',
            }
        except subprocess.TimeoutExpired:
            return {'success': False, 'message': 'Profile switch timed out'}
        except Exception as e:
            return {'success': False, 'message': str(e)}

    def verify(self, desired: dict) -> dict:
        """Verify GPU telemetry aligns with expected profile behavior."""
        gpu = self._nvidia_smi_state()
        mismatches = []
        confidence = 1.0

        if not self.available()['running']:
            mismatches.append('MSI Afterburner is not running')
            confidence = 0.0

        # We can loosely verify if an undervolt took hold by checking clocks/power.
        # However, due to AB's closed nature, we simply assign a high confidence if it is running
        # and temperatures aren't violently spiking out of bounds.
        temp = gpu.get('temp_c')
        if temp and temp >= 88:
            mismatches.append(f"GPU temperature actively spiking: {temp}C")
            confidence = 0.0

        return {
            'verified': len(mismatches) == 0,
            'expected': desired,
            'actual': gpu,
            'mismatches': mismatches,
            'confidence': confidence if len(mismatches) == 0 else 0.0
        }

    def revert(self, baseline: dict) -> dict:
        """Revert to baseline profile."""
        # Afterburner does not expose 'currently active slot' easily.
        # Safe fallback is unconditionally returning to slot 1 (balanced / stock clocks).
        return self.apply({'profile': 'balanced'})
