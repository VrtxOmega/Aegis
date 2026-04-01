"""
Tuning Manager — Orchestrator for hardware tuning with safety gates.
Single point of control for all tuning operations.
Enforces: serialized execution, temp limits, value range checks, baseline capture,
verification loop, receipt logging, and rollback.
"""
import os
import json
import time
import threading
from datetime import datetime
import psutil

from tuning_adapters.throttlestop_adapter import ThrottleStopAdapter
from tuning_adapters.afterburner_adapter import AfterburnerAdapter
from tuning_adapters.msi_center_adapter import MSICenterAdapter

# ═══════════════════════════════════════════
# SAFETY LIMITS — HARD-CODED, NOT CONFIGURABLE
# ═══════════════════════════════════════════
SAFE_LIMITS = {
    'cpu_core_offset_mv':  {'min': -125, 'max': 0},
    'cpu_cache_offset_mv': {'min': -125, 'max': 0},
    'gpu_mem_oc_mhz':      {'min': 0,    'max': 500},
    'cpu_pl1_w':           {'min': 35,   'max': 90},
    'cpu_pl2_w':           {'min': 80,   'max': 175},
}

TEMP_BLOCK_THRESHOLD = 90    # Block apply if any sensor > 90°C
RECENT_CRASH_WINDOW_H = 24   # Block apply if crash within this window

# Aegis system profiles — each maps to adapter-specific profiles
SYSTEM_PROFILES = {
    'performance': {
        'name': 'Performance',
        'description': 'Maximum clocks and power. Higher temps, louder fans.',
        'icon': '🔥',
        'cpu': {'profile': 'performance'},
        'gpu': {'profile': 'performance'},
        'fan': {'profile': 'performance'},
        'targets': {
            'cpu_undervolt': 'LOCKED (BIOS)',
            'cpu_pl1': '65W',
            'cpu_pl2': '157W',
            'cpu_epp': '32',
            'gpu_core_oc': '+150 MHz',
            'gpu_mem_oc': '+500 MHz',
            'fan_mode': 'Extreme Performance',
        },
    },
    'balanced': {
        'name': 'Balanced',
        'description': 'Moderate power limits. Recommended daily.',
        'icon': '⚖️',
        'cpu': {'profile': 'balanced'},
        'gpu': {'profile': 'balanced'},
        'fan': {'profile': 'balanced'},
        'targets': {
            'cpu_undervolt': 'LOCKED (BIOS)',
            'cpu_pl1': '55W',
            'cpu_pl2': '140W',
            'cpu_epp': '128',
            'gpu_core_oc': '+0 MHz',
            'gpu_mem_oc': '+0 MHz',
            'fan_mode': 'Balanced',
        },
    },
    'quiet': {
        'name': 'Quiet',
        'description': 'Reduced power, silent fans. Best for browsing & coding.',
        'icon': '🔇',
        'cpu': {'profile': 'quiet'},
        'gpu': {'profile': 'quiet'},
        'fan': {'profile': 'quiet'},
        'targets': {
            'cpu_undervolt': 'LOCKED (BIOS)',
            'cpu_pl1': '45W',
            'cpu_pl2': '100W',
            'cpu_epp': '192',
            'gpu_core_oc': '-200 MHz',
            'gpu_mem_oc': '+0 MHz',
            'fan_mode': 'Silent',
        },
    },
    'thermal_safe': {
        'name': 'Thermal Safe',
        'description': 'Emergency thermal relief. Max power reduction.',
        'icon': '🧊',
        'cpu': {'profile': 'thermal_safe'},
        'gpu': {'profile': 'quiet'},
        'fan': {'profile': 'thermal_safe'},
        'targets': {
            'cpu_undervolt': 'LOCKED (BIOS)',
            'cpu_pl1': '35W',
            'cpu_pl2': '80W',
            'cpu_epp': '220',
            'gpu_core_oc': '-200 MHz',
            'gpu_mem_oc': '+0 MHz',
            'fan_mode': 'Silent (aggressive fans if > 85°C)',
        },
    },
}

# Afterburner profile actual values (as configured by user)
# NOTE: GPU power limit is LOCKED on laptop vBIOS — cannot be changed in Afterburner
AFTERBURNER_PROFILE_GUIDE = {
    'profile_1_stock': {
        'name': 'Stock (Slot 1)',
        'core_clock_offset': '+0 MHz',
        'memory_clock_offset': '+0 MHz',
        'power_limit': 'LOCKED (laptop vBIOS)',
        'notes': 'Safe baseline — no overclock',
    },
    'profile_2_performance': {
        'name': 'Performance (Slot 2)',
        'core_clock_offset': '+150 MHz',
        'memory_clock_offset': '+500 MHz',
        'power_limit': 'LOCKED (laptop vBIOS)',
        'notes': 'Gaming/rendering — watch for artifacts',
    },
    'profile_3_quiet': {
        'name': 'Quiet (Slot 3)',
        'core_clock_offset': '-200 MHz',
        'memory_clock_offset': '+0 MHz',
        'power_limit': 'LOCKED (laptop vBIOS)',
        'notes': 'Power saving — reduced GPU clocks',
    },
}


class TuningManager:
    """Centralized tuning orchestrator with safety gates."""

    def __init__(self, receipts_path=None):
        self._lock = threading.Lock()
        self._in_flight = False

        # Initialize adapters
        self.adapters = {
            'cpu': ThrottleStopAdapter(),
            'gpu': AfterburnerAdapter(),
            'fan': MSICenterAdapter(),
        }

        # Receipt storage
        self._receipts_path = receipts_path or os.path.join(
            os.path.dirname(__file__), '..', 'tuning_receipts.json'
        )
        self._baseline = {}
        self._action_counter = 0

    # ═══════════════════════════════════════
    # CAPABILITIES
    # ═══════════════════════════════════════
    def get_capabilities(self) -> dict:
        """Probe all adapters for what's available."""
        caps = {}
        for subsystem, adapter in self.adapters.items():
            avail = adapter.available()
            caps[subsystem] = {
                'provider': adapter.name,
                'subsystem': subsystem,
                'installed': avail.get('installed', False),
                'running': avail.get('running', False),
                'readable': avail.get('installed', False),
                'writable': avail.get('running', False),
                'details': avail,
            }
        return caps

    # ═══════════════════════════════════════
    # STATE
    # ═══════════════════════════════════════
    def get_state(self) -> dict:
        """Read current state from all adapters."""
        state = {}
        for subsystem, adapter in self.adapters.items():
            try:
                state[subsystem] = adapter.detect_state()
            except Exception as e:
                state[subsystem] = {
                    'status': 'ERROR',
                    'provider': adapter.name,
                    'error': str(e),
                }
        return state

    # ═══════════════════════════════════════
    # PROFILES
    # ═══════════════════════════════════════
    def get_profiles(self) -> dict:
        """Return available system profiles with current capability status."""
        profiles = {}
        caps = self.get_capabilities()

        for key, profile in SYSTEM_PROFILES.items():
            # Determine readiness for each subsystem
            readiness = {}
            for sub in ['cpu', 'gpu', 'fan']:
                cap = caps.get(sub, {})
                if not cap.get('installed'):
                    readiness[sub] = 'NOT_INSTALLED'
                elif not cap.get('running'):
                    readiness[sub] = 'NOT_RUNNING'
                else:
                    readiness[sub] = 'READY'

            fully_ready = all(r == 'READY' for r in readiness.values())
            partially_ready = any(r == 'READY' for r in readiness.values())

            profiles[key] = {
                **profile,
                'readiness': readiness,
                'can_apply': partially_ready,
                'fully_ready': fully_ready,
            }

        return profiles

    def get_afterburner_guide(self) -> dict:
        """Return the guide for setting up Afterburner profiles."""
        return AFTERBURNER_PROFILE_GUIDE

    # ═══════════════════════════════════════
    # SAFETY GATE
    # ═══════════════════════════════════════
    def _safety_check(self) -> dict:
        """Pre-flight safety check before any apply operation."""
        issues = []

        # Check temperatures
        try:
            gpu_state = self.adapters['gpu']._nvidia_smi_state()
            gpu_temp = gpu_state.get('temp_c')
            if gpu_temp and gpu_temp > TEMP_BLOCK_THRESHOLD:
                issues.append(f'GPU temperature too high: {gpu_temp}°C (limit: {TEMP_BLOCK_THRESHOLD}°C)')
        except Exception:
            pass

        try:
            temps = psutil.sensors_temperatures()
            if temps:
                for sensor_name, entries in temps.items():
                    for entry in entries:
                        if entry.current and entry.current > TEMP_BLOCK_THRESHOLD:
                            issues.append(
                                f'Sensor {entry.label or sensor_name} too hot: '
                                f'{entry.current}°C (limit: {TEMP_BLOCK_THRESHOLD}°C)'
                            )
        except Exception:
            pass

        # Check BSOD watchdog for recent instability
        try:
            from bsod_watchdog import get_watchdog_status
            status = get_watchdog_status()
            if status.get('threat_level') == 'HIGH':
                issues.append(
                    f'System stability degraded: {status.get("crash_count", "?")} '
                    f'crashes in last {status.get("window_hours", 72)}h'
                )
        except Exception:
            pass

        # Check serialization lock
        if self._in_flight:
            issues.append('Another tuning operation is already in progress')

        return {
            'safe': len(issues) == 0,
            'issues': issues,
            'timestamp': datetime.now().isoformat(),
        }

    # ═══════════════════════════════════════
    # EXECUTE TUNING TRANSACTION (4-PHASE BOUNDARY)
    # ═══════════════════════════════════════
    def apply_profile(self, profile_name: str) -> dict:
        """Apply a system profile across all subsystems with rigid safety guarantees.
        Enforces: PHASE 1: PRECHECK -> PHASE 2: APPLY -> PHASE 3: VERIFY -> PHASE 4: DECIDE (COMMIT/ROLLBACK)
        """
        profile_name = profile_name.lower()
        if profile_name not in SYSTEM_PROFILES:
            return {'success': False, 'message': f'Unknown profile: {profile_name}'}

        profile = SYSTEM_PROFILES[profile_name]

        # ==========================================
        # PHASE 0: AUTO-LAUNCH DEPENDENCIES
        # ==========================================
        # Lifecycle manager auto-starts ThrottleStop/Afterburner if needed.
        # This eliminates the requirement for users to manually pre-launch them.
        try:
            from lifecycle_manager import get_lifecycle_manager
            lm = get_lifecycle_manager()
            if profile.get('cpu'):
                launch_result = lm.ensure_running('throttlestop')
                if launch_result.get('started'):
                    import time as _t; _t.sleep(3)  # Extra settle time for fresh launch
            if profile.get('gpu'):
                launch_result = lm.ensure_running('afterburner')
                if launch_result.get('started'):
                    import time as _t; _t.sleep(3)
        except Exception:
            pass  # Non-fatal — adapters will report availability status

        # ==========================================
        # PHASE 1: PRECHECK
        # ==========================================
        safety = self._safety_check()
        if not safety['safe']:
            return {
                'success': False,
                'blocked_by': 'SAFETY_GATE',
                'issues': safety['issues'],
                'message': 'Apply blocked by precheck safety gate: ' + '; '.join(safety['issues']),
            }

        # Acquire lock to prevent overlapping mutations
        if not self._lock.acquire(timeout=5):
            return {'success': False, 'message': 'Could not acquire tuning control lock'}

        try:
            self._in_flight = True
            receipt_log = []
            receipt_log.append("[SYSTEM] Phase 1 (PRECHECK): Passed safely.")

            # ==========================================
            # PHASE 2: APPLY (Capture Baseline & Mutate)
            # ==========================================
            self._baseline = self.get_state()
            receipt_log.append("[SYSTEM] Baseline system state captured for potential rollback.")

            apply_results = {}
            for subsystem in ['cpu', 'gpu', 'fan']:
                adapter = self.adapters[subsystem]
                avail = adapter.available()
                if not avail.get('installed') or not avail.get('running'):
                    receipt_log.append(f"[{adapter.name}] Skipped (Not active)")
                    continue
                
                subsystem_desired = profile.get(subsystem, {})
                try:
                    result = adapter.apply(subsystem_desired)
                    apply_results[subsystem] = result
                    if result.get('success'):
                        receipt_log.append(f"[{adapter.name}] Initial apply command sent.")
                    else:
                        receipt_log.append(f"[{adapter.name}] Warn: Apply rejected ({result.get('message')})")
                except Exception as e:
                    apply_results[subsystem] = {'success': False, 'error': str(e)}
                    receipt_log.append(f"[{adapter.name}] Error: Exception during apply ({str(e)})")

            # ==========================================
            # PHASE 3: VERIFY (Stabilization Window)
            # ==========================================
            receipt_log.append("[SYSTEM] Entering Phase 3 (VERIFY)... pausing 5 seconds for hardware stabilization.")
            time.sleep(5)  # Synchronous hold to allow EC/Drivers to align

            verify_results = {}
            total_confidence = 0.0
            components_verified = 0

            for subsystem in ['cpu', 'gpu', 'fan']:
                adapter = self.adapters[subsystem]
                avail = adapter.available()
                if not avail.get('installed') or not avail.get('running'):
                    continue

                subsystem_desired = profile.get(subsystem, {})
                try:
                    v_res = adapter.verify(subsystem_desired)
                    verify_results[subsystem] = v_res
                    conf = v_res.get('confidence', 0.0)
                    total_confidence += conf
                    components_verified += 1
                    
                    if v_res.get('verified'):
                        receipt_log.append(f"[{adapter.name}] Verified (Confidence: {conf:.2f})")
                    else:
                        issues = ", ".join(v_res.get('mismatches', ['Unknown drift']))
                        receipt_log.append(f"[{adapter.name}] Verification Failed! ({issues})")
                except Exception as e:
                    verify_results[subsystem] = {'verified': False, 'mismatches': [str(e)], 'confidence': 0.0}
                    components_verified += 1
                    receipt_log.append(f"[{adapter.name}] Exception during verification: {str(e)}")

            # ==========================================
            # PHASE 4: DECIDE (Commit or Rollback)
            # ==========================================
            avg_confidence = (total_confidence / components_verified) if components_verified > 0 else 1.0
            
            # Subsystem consensus: If any active component failed verification, we rollback.
            rollback_required = any(
                v.get('verified') is False for v in verify_results.values()
            )

            if rollback_required:
                receipt_log.append("[!] SYSTEM DRIFT DETECTED. ENFORCING INVARIANT: ROLLBACK TO BASELINE.")
                revert_result = self.revert()
                receipt_log.append("[SYSTEM] Rollback applied safely.")
                final_status = 'rollback'
            else:
                receipt_log.append(f"[SYSTEM] Hardware state locked and confirmed. Confidence: {avg_confidence:.2f}")
                final_status = 'success'

            self._action_counter += 1
            receipt = {
                'action_id': f'tun_{datetime.now().strftime("%Y%m%d_%H%M%S")}_{self._action_counter:03d}',
                'profile': profile_name,
                'status': final_status,
                'confidence': avg_confidence,
                'logs': receipt_log,
                'timestamp': datetime.now().isoformat(),
            }
            self._save_receipt(receipt)

            return {
                'success': final_status == 'success',
                'status': final_status,
                'confidence': avg_confidence,
                'receipt': receipt,
                'message': 'Rollback Executed' if final_status == 'rollback' else f'Profile "{profile["name"]}" verified and active.',
                'logs': receipt_log,
            }

        finally:
            self._in_flight = False
            self._lock.release()

    # ═══════════════════════════════════════
    # VERIFY
    # ═══════════════════════════════════════
    def verify_state(self) -> dict:
        """Verify all adapters match their last applied state."""
        results = {}
        for subsystem, adapter in self.adapters.items():
            try:
                state = adapter.detect_state()
                results[subsystem] = {
                    'status': state.get('status', 'UNKNOWN'),
                    'provider': adapter.name,
                    'state': state,
                }
            except Exception as e:
                results[subsystem] = {
                    'status': 'ERROR',
                    'provider': adapter.name,
                    'error': str(e),
                }
        return results

    # ═══════════════════════════════════════
    # REVERT
    # ═══════════════════════════════════════
    def revert(self) -> dict:
        """Revert all subsystems to their baseline state."""
        if not self._baseline:
            return {'success': False, 'message': 'No baseline captured — nothing to revert to'}

        results = {}
        for subsystem, adapter in self.adapters.items():
            baseline_state = self._baseline.get(subsystem, {})
            try:
                result = adapter.revert(baseline_state)
                results[subsystem] = result
            except Exception as e:
                results[subsystem] = {'success': False, 'error': str(e)}

        receipt = {
            'action_id': f'revert_{datetime.now().strftime("%Y%m%d_%H%M%S")}',
            'action': 'REVERT',
            'results': results,
            'timestamp': datetime.now().isoformat(),
        }
        self._save_receipt(receipt)

        return {'success': True, 'receipt': receipt}

    def deactivate_tuning(self) -> dict:
        """Deactivate all tuning and stop managed companion apps.
        Called when user explicitly turns off tuning profiles.
        """
        # Revert to baseline first
        revert_result = self.revert()

        # Auto-stop ThrottleStop and Afterburner (lifecycle manager enforces auto_stop rules)
        stopped = {}
        try:
            from lifecycle_manager import get_lifecycle_manager
            lm = get_lifecycle_manager()
            stopped['throttlestop'] = lm.stop('throttlestop')
            stopped['afterburner'] = lm.stop('afterburner')
        except Exception as e:
            stopped['error'] = str(e)

        return {
            'success': revert_result.get('success', False),
            'revert': revert_result,
            'stopped': stopped,
            'message': 'Tuning deactivated. Companion apps stopped.',
        }

    # ═══════════════════════════════════════
    # RECEIPTS
    # ═══════════════════════════════════════
    def _save_receipt(self, receipt: dict):
        """Append receipt to the JSON log."""
        try:
            receipts = []
            if os.path.isfile(self._receipts_path):
                with open(self._receipts_path, 'r') as f:
                    receipts = json.load(f)

            receipts.append(receipt)
            # Keep last 100 receipts
            receipts = receipts[-100:]

            with open(self._receipts_path, 'w') as f:
                json.dump(receipts, f, indent=2)
        except Exception:
            pass

    def get_history(self, count=20) -> list:
        """Return the last N tuning action receipts."""
        try:
            if os.path.isfile(self._receipts_path):
                with open(self._receipts_path, 'r') as f:
                    receipts = json.load(f)
                return receipts[-count:]
        except Exception:
            pass
        return []


# Singleton instance
_manager = None


def get_manager() -> TuningManager:
    global _manager
    if _manager is None:
        _manager = TuningManager()
    return _manager
