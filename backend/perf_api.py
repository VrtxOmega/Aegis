"""
Performance tuning API for Aegis.
Read-only monitoring + launcher integration for ThrottleStop, MSI Afterburner, MSI Center.
"""
import os
import re
import json
import subprocess
from flask import Blueprint, jsonify, request

perf_bp = Blueprint('performance', __name__)

# ────────────────────────────────────────
# Tool Paths
# ────────────────────────────────────────
THROTTLESTOP_PATH = None
AFTERBURNER_PATH = r'C:\Program Files (x86)\MSI Afterburner\MSIAfterburner.exe'
MSI_CENTER_PATH = r'C:\Program Files\WindowsApps\9426MICRO-STARINTERNATION.MSICenter_2.0.68.0_x64__kzh8wxbdkxb8p\MSI Center.exe'

# Find ThrottleStop
for candidate in [
    os.path.expandvars(r'%LOCALAPPDATA%\Microsoft\WinGet\Links\ThrottleStop.exe'),
    os.path.expandvars(r'%LOCALAPPDATA%\Programs\ThrottleStop\ThrottleStop.exe'),
    r'C:\ThrottleStop\ThrottleStop.exe',
]:
    if os.path.isfile(candidate):
        THROTTLESTOP_PATH = candidate
        break


def _tool_status():
    """Check which performance tools are available."""
    tools = {
        'throttlestop': {
            'installed': THROTTLESTOP_PATH is not None,
            'path': THROTTLESTOP_PATH,
            'purpose': 'CPU voltage offset & power limit tuning',
        },
        'afterburner': {
            'installed': os.path.isfile(AFTERBURNER_PATH),
            'path': AFTERBURNER_PATH if os.path.isfile(AFTERBURNER_PATH) else None,
            'purpose': 'GPU voltage/frequency curve & memory OC',
        },
        'msi_center': {
            'installed': os.path.isfile(MSI_CENTER_PATH),
            'path': MSI_CENTER_PATH if os.path.isfile(MSI_CENTER_PATH) else None,
            'purpose': 'Fan curves & performance profiles',
        },
    }
    return tools


def _get_cpu_info():
    """Get CPU frequency, core count, and current power state."""
    try:
        import psutil
        freq = psutil.cpu_freq()
        cpu_percent = psutil.cpu_percent(interval=0.5, percpu=True)
        temps = {}
        try:
            t = psutil.sensors_temperatures()
            if t:
                for name, entries in t.items():
                    for e in entries:
                        temps[e.label or name] = {
                            'current': e.current,
                            'high': e.high,
                            'critical': e.critical,
                        }
        except Exception:
            pass

        return {
            'current_mhz': freq.current if freq else None,
            'max_mhz': freq.max if freq else None,
            'min_mhz': freq.min if freq else None,
            'cores_physical': psutil.cpu_count(logical=False),
            'cores_logical': psutil.cpu_count(logical=True),
            'per_core_percent': cpu_percent,
            'avg_percent': sum(cpu_percent) / len(cpu_percent) if cpu_percent else 0,
            'temperatures': temps,
        }
    except Exception as e:
        return {'error': str(e)}


def _get_gpu_info():
    """Get GPU frequency, voltage, temperature, power from nvidia-smi."""
    try:
        result = subprocess.run(
            ['nvidia-smi',
             '--query-gpu=clocks.gr,clocks.max.gr,clocks.mem,clocks.max.mem,'
             'temperature.gpu,power.draw,power.limit,fan.speed,'
             'utilization.gpu,utilization.memory,memory.used,memory.total',
             '--format=csv,noheader,nounits'],
            capture_output=True, text=True, timeout=10
        )
        if result.returncode != 0:
            return {'error': 'nvidia-smi failed: ' + result.stderr[:200]}

        values = [v.strip() for v in result.stdout.strip().split(',')]
        if len(values) < 12:
            return {'error': f'Incomplete nvidia-smi data: got {len(values)} fields'}

        def safe_float(v):
            try:
                if '[N/A]' in str(v) or 'N/A' in str(v):
                    return None
                return float(v)
            except (ValueError, TypeError):
                return None

        return {
            'clock_mhz': safe_float(values[0]),
            'max_clock_mhz': safe_float(values[1]),
            'mem_clock_mhz': safe_float(values[2]),
            'max_mem_clock_mhz': safe_float(values[3]),
            'temperature_c': safe_float(values[4]),
            'power_draw_w': safe_float(values[5]),
            'power_limit_w': safe_float(values[6]),
            'fan_speed_percent': safe_float(values[7]),
            'gpu_util_percent': safe_float(values[8]),
            'mem_util_percent': safe_float(values[9]),
            'vram_used_mb': safe_float(values[10]),
            'vram_total_mb': safe_float(values[11]),
        }
    except Exception as e:
        return {'error': str(e)}


# ────────────────────────────────────────
# Hardware-specific tuning profiles
# MSI Raider GE78HX 13VH
# ────────────────────────────────────────

TUNING_PROFILES = {
    'cpu_undervolt': {
        'name': 'CPU Undervolt',
        'description': 'Core voltage offset for i9-13950HX via ThrottleStop',
        'tool': 'ThrottleStop',
        'safe_start': '-60 mV',
        'typical_floor': '-80 to -120 mV',
        'max_aggressive': '-150 mV',
        'settings': {
            'CPU Core': 'Adaptive, -60 mV offset',
            'CPU P-Cache': 'Adaptive, -60 mV offset (match Core)',
            'CPU E-Cache': 'Adaptive, -60 mV offset (match Core)',
        },
        'expected_results': {
            'temp_reduction': '8-15°C under load',
            'perf_impact': '0% (sustained clocks may increase)',
            'power_reduction': '10-25W',
        },
        'stability_test': 'Cinebench R23 multi-core × 3 runs',
    },
    'gpu_undervolt': {
        'name': 'GPU Undervolt / Curve',
        'description': 'Voltage-Frequency curve for RTX 4070 via MSI Afterburner',
        'tool': 'MSI Afterburner',
        'settings': {
            'Target Voltage': '900 mV',
            'Target Frequency': '2250 MHz',
            'Memory OC': '+500 MHz (safe), +750 MHz (test)',
        },
        'expected_results': {
            'temp_reduction': '8-15°C under load',
            'noise_reduction': 'Significantly quieter fans',
            'perf_impact': '0% to +5% (less thermal throttling)',
            'power_reduction': '15-25W',
        },
        'stability_test': 'Unigine Heaven 30 min loop',
    },
    'fan_curve': {
        'name': 'Custom Fan Curve',
        'description': 'Optimized fan ramp for quiet operation with thermal safety',
        'tool': 'MSI Center',
        'curve': [
            {'temp': 50, 'cpu_fan': 0, 'gpu_fan': 0, 'label': 'Silent'},
            {'temp': 65, 'cpu_fan': 30, 'gpu_fan': 25, 'label': 'Whisper'},
            {'temp': 75, 'cpu_fan': 50, 'gpu_fan': 45, 'label': 'Balanced'},
            {'temp': 85, 'cpu_fan': 70, 'gpu_fan': 65, 'label': 'Active'},
            {'temp': 95, 'cpu_fan': 90, 'gpu_fan': 85, 'label': 'Aggressive'},
            {'temp': 100, 'cpu_fan': 100, 'gpu_fan': 100, 'label': 'Cooler Boost'},
        ],
    },
    'power_limits': {
        'name': 'Power Limits',
        'description': 'CPU PL1/PL2 adjustment for thermal headroom',
        'tool': 'ThrottleStop (TPL)',
        'settings': {
            'PL1 (Long Duration)': '55W (stock) — adjust if needed',
            'PL2 (Short Duration)': '157W stock → 120W for thermal relief',
            'Tau (Duration)': '28s stock',
        },
        'notes': 'Reducing PL2 to 120W has minimal gaming impact but drops peak temp by 5-10°C',
    },
}


@perf_bp.route('/status', methods=['GET'])
def perf_status():
    """Get performance tuning status: tools, current CPU/GPU state."""
    return jsonify({
        'tools': _tool_status(),
        'cpu': _get_cpu_info(),
        'gpu': _get_gpu_info(),
    })


@perf_bp.route('/profiles', methods=['GET'])
def get_profiles():
    """Get recommended tuning profiles for this hardware."""
    return jsonify({
        'hardware': {
            'cpu': 'Intel Core i9-13950HX',
            'gpu': 'NVIDIA GeForce RTX 4070 Laptop',
            'ram': '32GB DDR5',
            'chassis': 'MSI Raider GE78HX 13VH',
        },
        'profiles': TUNING_PROFILES,
    })


