import psutil
import time
import datetime
from flask import Blueprint, jsonify

system_bp = Blueprint('system', __name__)

@system_bp.route('/status')
def get_system_status():
    cpu_percent = psutil.cpu_percent(interval=1)
    ram = psutil.virtual_memory()
    ram_percent = ram.percent
    ram_used_gb = round(ram.used / (1024**3), 2)
    ram_total_gb = round(ram.total / (1024**3), 2)

    # Uptime
    boot_ts = psutil.boot_time()
    boot_dt = datetime.datetime.fromtimestamp(boot_ts)
    boot_time_str = boot_dt.strftime('%b %d, %I:%M %p')
    uptime_sec = int(time.time() - boot_ts)
    days = uptime_sec // 86400
    hours = (uptime_sec % 86400) // 3600
    minutes = (uptime_sec % 3600) // 60
    parts = []
    if days > 0: parts.append(f'{days}d')
    if hours > 0: parts.append(f'{hours}h')
    parts.append(f'{minutes}m')
    uptime_string = ' '.join(parts)

    disk_usage = []
    for part in psutil.disk_partitions():
        if 'cdrom' in part.opts or part.fstype == '':
            continue
        try:
            usage = psutil.disk_usage(part.mountpoint)
            disk_usage.append({
                'device': part.device,
                'mountpoint': part.mountpoint,
                'percent': usage.percent,
                'free_gb': round(usage.free / (1024**3), 2),
                'total_gb': round(usage.total / (1024**3), 2)
            })
        except PermissionError:
            continue

    return jsonify({
        'cpu_percent': cpu_percent,
        'ram_percent': ram_percent,
        'ram_used_gb': ram_used_gb,
        'ram_total_gb': ram_total_gb,
        'boot_time': boot_time_str,
        'uptime_string': uptime_string,
        'disk_usage': disk_usage
    })
