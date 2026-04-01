"""
Aegis — Hardware Health API Blueprint
Endpoints: temperatures, battery, disks, gpu
Target: MSI Raider GE78 HX 13V — i9-13950HX + RTX 4070 + 32GB DDR5
"""
import subprocess
import json
import psutil
from flask import Blueprint, jsonify

hardware_bp = Blueprint('hardware', __name__)


@hardware_bp.route('/temperatures')
def get_temperatures():
    """CPU/system temperatures.
    Windows: psutil doesn't support sensors_temperatures.
    Fallback: WMI via PowerShell for thermal zones.
    """
    try:
        temps = {}

        # Try psutil first (works on Linux)
        if hasattr(psutil, 'sensors_temperatures'):
            sensor_temps = psutil.sensors_temperatures()
            if sensor_temps:
                for name, entries in sensor_temps.items():
                    for entry in entries:
                        temps[entry.label or name] = {
                            'current': entry.current,
                            'high': entry.high,
                            'critical': entry.critical
                        }
                return jsonify({'temperatures': temps, 'source': 'psutil'})

        # Windows fallback: WMI thermal zone
        try:
            cmd = 'Get-CimInstance -Namespace root/WMI -ClassName MSAcpi_ThermalZoneTemperature 2>$null | Select-Object InstanceName, CurrentTemperature | ConvertTo-Json'
            result = subprocess.run(
                ['powershell', '-NoProfile', '-Command', cmd],
                capture_output=True, text=True, timeout=5
            )
            if result.returncode == 0 and result.stdout.strip():
                data = json.loads(result.stdout)
                if not isinstance(data, list):
                    data = [data]
                for zone in data:
                    name = zone.get('InstanceName', 'Thermal Zone')
                    # WMI returns temp in tenths of Kelvin
                    kelvin_tenths = zone.get('CurrentTemperature', 0)
                    celsius = round((kelvin_tenths / 10) - 273.15, 1)
                    temps[name] = {'current': celsius, 'high': None, 'critical': None}
        except Exception:
            pass

        # Also try to get CPU package temp from nvidia-smi (GPU temp)
        gpu_temp = _get_nvidia_gpu_temp()
        if gpu_temp is not None:
            temps['GPU'] = {'current': gpu_temp, 'high': 90, 'critical': 95}

        if not temps:
            return jsonify({'temperatures': {}, 'source': 'unavailable',
                          'note': 'Install Open Hardware Monitor or HWiNFO for detailed temps'})

        return jsonify({'temperatures': temps, 'source': 'wmi'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


def _get_nvidia_gpu_temp():
    """Extract GPU temp from nvidia-smi."""
    try:
        result = subprocess.run(
            ['nvidia-smi', '--query-gpu=temperature.gpu', '--format=csv,noheader,nounits'],
            capture_output=True, text=True, timeout=3
        )
        if result.returncode == 0:
            return float(result.stdout.strip())
    except Exception:
        pass
    return None


@hardware_bp.route('/gpu')
def get_gpu():
    """NVIDIA GPU stats via nvidia-smi.
    Returns: name, temp, utilization, VRAM used/total, driver version, fan speed.
    """
    try:
        cmd = 'nvidia-smi --query-gpu=name,temperature.gpu,utilization.gpu,memory.used,memory.total,driver_version,fan.speed,power.draw,power.limit --format=csv,noheader,nounits'
        result = subprocess.run(
            cmd.split(),
            capture_output=True, text=True, timeout=5
        )
        if result.returncode != 0:
            return jsonify({'error': 'nvidia-smi not available', 'gpu': None})

        parts = [p.strip() for p in result.stdout.strip().split(',')]
        if len(parts) >= 9:
            gpu = {
                'name': parts[0],
                'temperature_c': float(parts[1]),
                'utilization_percent': float(parts[2]),
                'vram_used_mb': float(parts[3]),
                'vram_total_mb': float(parts[4]),
                'driver_version': parts[5],
                'fan_speed_percent': float(parts[6]) if parts[6] != '[N/A]' else None,
                'power_draw_w': float(parts[7]) if parts[7] != '[N/A]' else None,
                'power_limit_w': float(parts[8]) if parts[8] != '[N/A]' else None,
            }
            return jsonify({'gpu': gpu})
        return jsonify({'error': 'Unexpected nvidia-smi output', 'gpu': None})
    except Exception as e:
        return jsonify({'error': str(e), 'gpu': None}), 500


@hardware_bp.route('/battery')
def get_battery():
    """Battery status, percent, and time remaining."""
    try:
        battery = psutil.sensors_battery()
        if battery is None:
            return jsonify({'battery': None, 'note': 'No battery detected (desktop mode?)'})

        secs_left = battery.secsleft
        if secs_left == psutil.POWER_TIME_UNLIMITED:
            time_remaining = 'Charging'
        elif secs_left == psutil.POWER_TIME_UNKNOWN:
            time_remaining = 'Unknown'
        else:
            hours = secs_left // 3600
            minutes = (secs_left % 3600) // 60
            time_remaining = f'{int(hours)}h {int(minutes)}m'

        return jsonify({
            'battery': {
                'percent': battery.percent,
                'plugged_in': battery.power_plugged,
                'time_remaining': time_remaining
            }
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@hardware_bp.route('/disks')
def get_disks():
    """Disk health and SMART status."""
    try:
        disks = []

        # Get partition info from psutil
        for part in psutil.disk_partitions():
            if 'cdrom' in part.opts or part.fstype == '':
                continue
            try:
                usage = psutil.disk_usage(part.mountpoint)
                disk_info = {
                    'device': part.device,
                    'mountpoint': part.mountpoint,
                    'fstype': part.fstype,
                    'total_gb': round(usage.total / (1024**3), 1),
                    'used_gb': round(usage.used / (1024**3), 1),
                    'free_gb': round(usage.free / (1024**3), 1),
                    'percent': usage.percent,
                    'smart_status': 'Unknown'
                }
                disks.append(disk_info)
            except PermissionError:
                continue

        # Try WMIC for SMART status
        try:
            result = subprocess.run(
                ['wmic', 'diskdrive', 'get', 'model,status', '/format:csv'],
                capture_output=True, text=True, timeout=5
            )
            if result.returncode == 0:
                lines = [l.strip() for l in result.stdout.strip().split('\n') if l.strip() and ',' in l]
                for line in lines[1:]:  # Skip header
                    parts = line.split(',')
                    if len(parts) >= 3:
                        model = parts[1].strip()
                        status = parts[2].strip()
                        # Tag matching disks with SMART status
                        for d in disks:
                            d['smart_status'] = status if status else 'Unknown'
        except Exception:
            pass

        return jsonify({'disks': disks})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@hardware_bp.route('/memory')
def get_memory():
    """Detailed memory info — DDR5 specific stats."""
    try:
        vm = psutil.virtual_memory()
        swap = psutil.swap_memory()
        return jsonify({
            'memory': {
                'total_gb': round(vm.total / (1024**3), 1),
                'available_gb': round(vm.available / (1024**3), 1),
                'used_gb': round(vm.used / (1024**3), 1),
                'percent': vm.percent,
                'swap_total_gb': round(swap.total / (1024**3), 1),
                'swap_used_gb': round(swap.used / (1024**3), 1),
                'swap_percent': swap.percent
            }
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500
