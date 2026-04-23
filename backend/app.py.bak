import os
import subprocess
import time
from flask import Flask, jsonify, request, g
from flask_cors import CORS

from db import init_app, get_db, close_db
from system_api import system_bp
from projects_api import projects_bp
from weather_api import weather_bp
from security_api import security_bp
from hardware_api import hardware_bp
from threat_api import threat_bp
from ai_engine import ai_bp, start_watchdog
from defense_api import defense_bp
from scanner_api import scanner_bp
from vpn_api import vpn_bp
from perf_api import perf_bp
from tuning_api import tuning_bp
from report_api import report_bp
from correlation_api import correlation_bp
from lifecycle_api import lifecycle_bp
from bsod_watchdog import start_watchdog as start_bsod_watchdog, get_watchdog_status

app = Flask(__name__)
CORS(app)

# Initialize database
init_app(app)

# Register blueprints
app.register_blueprint(system_bp, url_prefix='/api/system')
app.register_blueprint(projects_bp, url_prefix='/api/projects')
app.register_blueprint(weather_bp, url_prefix='/api/weather')
app.register_blueprint(security_bp, url_prefix='/api/security')
app.register_blueprint(hardware_bp, url_prefix='/api/hardware')
app.register_blueprint(threat_bp, url_prefix='/api/threats')
app.register_blueprint(ai_bp, url_prefix='/api/ai')
app.register_blueprint(defense_bp, url_prefix='/api/defense')
app.register_blueprint(scanner_bp, url_prefix='/api/scanner')
app.register_blueprint(vpn_bp, url_prefix='/api/vpn')
app.register_blueprint(perf_bp, url_prefix='/api/performance')
app.register_blueprint(tuning_bp, url_prefix='/api/tuning')
app.register_blueprint(report_bp)
app.register_blueprint(correlation_bp)
app.register_blueprint(lifecycle_bp)

# Auto-lifecycle: ensure Ollama is running (non-blocking, never stops it)
# Replaces the old always-on watchdog thread — Ollama lifecycle is now
# managed by lifecycle_manager.py with on-demand startup.
from lifecycle_manager import get_lifecycle_manager
_lm = get_lifecycle_manager()
_lm.ensure_running('ollama')  # Idempotent — does nothing if already running

# Start BSOD prevention watchdog (monitors NDIS filter re-registration + crash precursors)
start_bsod_watchdog(interval=300)

@app.route('/api/health')
def health():
    return jsonify({'status': 'ok'})

@app.route('/api/stability')
def stability():
    """System stability status — crash history, NDIS filter audit, threat level."""
    return jsonify(get_watchdog_status())

# Function to kill process on port 5000 (Windows specific)
def kill_port_owner(port=5000):
    try:
        # Find process using the port
        cmd = f'netstat -ano | findstr :{port}'
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True, check=True)
        output_lines = result.stdout.strip().split('\n')

        pids_to_kill = set()
        for line in output_lines:
            if 'LISTENING' in line:
                parts = line.strip().split()
                if parts and len(parts) > 4:
                    pid = parts[-1]
                    if pid.isdigit():
                        pids_to_kill.add(pid)
        
        for pid in pids_to_kill:
            # Get process image name
            cmd_tasklist = f'tasklist /FI "PID eq {pid}" /FO CSV /NH'
            tasklist_result = subprocess.run(cmd_tasklist, shell=True, capture_output=True, text=True, check=True)
            process_name = tasklist_result.stdout.strip().split(',')[0].strip('"')

            print(f"Attempting to kill process {pid} ({process_name}) on port {port}")
            subprocess.run(f'taskkill /F /PID {pid}', shell=True, check=True)
            print(f"Process {pid} killed.")

    except subprocess.CalledProcessError as e:
        print(f"No process found or error killing process on port {port}: {e}")
    except Exception as e:
        print(f"An unexpected error occurred: {e}")


if __name__ == '__main__':
    # Kill any existing process on port 5000 before starting Flask
    kill_port_owner(5000)
    # Give a moment for the port to free up
    time.sleep(1)
    # Use Waitress production WSGI server — i9-13950HX can handle 128 I/O-bound
    # threads easily. Most threads sleep on subprocess/Ollama I/O, not CPU work.
    from waitress import serve
    import logging
    logging.getLogger('waitress.queue').setLevel(logging.ERROR)
    logging.getLogger('waitress').setLevel(logging.ERROR)
    print(" * Serving Flask app 'app' via Waitress")
    print(" * Running on http://127.0.0.1:5000 (128 threads)")
    serve(app, host='127.0.0.1', port=5000, threads=128,
          connection_limit=1000, channel_timeout=300,
          recv_bytes=65536, send_bytes=65536)
