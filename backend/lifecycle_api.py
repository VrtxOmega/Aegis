"""
Aegis — Lifecycle API
Exposes dependency status and manual start/stop controls for the UI.
"""
from flask import Blueprint, jsonify, request
from lifecycle_manager import get_lifecycle_manager

lifecycle_bp = Blueprint('lifecycle', __name__)


@lifecycle_bp.route('/api/lifecycle/status', methods=['GET'])
def lifecycle_status():
    """Return status of all managed and passive dependencies."""
    mgr = get_lifecycle_manager()
    return jsonify(mgr.get_all_status())


@lifecycle_bp.route('/api/lifecycle/start/<app_name>', methods=['POST'])
def lifecycle_start(app_name):
    """Manually start a dependency."""
    mgr = get_lifecycle_manager()
    result = mgr.ensure_running(app_name)
    return jsonify(result)


@lifecycle_bp.route('/api/lifecycle/stop/<app_name>', methods=['POST'])
def lifecycle_stop(app_name):
    """Manually stop a dependency (only for auto_stop=True apps)."""
    mgr = get_lifecycle_manager()
    result = mgr.stop(app_name)
    return jsonify(result)
