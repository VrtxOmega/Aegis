"""
Tuning API — Flask blueprint for hardware tuning control.
All endpoints are thin wrappers around the TuningManager orchestrator.
"""
from flask import Blueprint, jsonify, request
from tuning_manager import get_manager

tuning_bp = Blueprint('tuning', __name__)


@tuning_bp.route('/capabilities', methods=['GET'])
def get_capabilities():
    """What tools are installed, what's readable/writable."""
    mgr = get_manager()
    return jsonify(mgr.get_capabilities())


@tuning_bp.route('/state', methods=['GET'])
def get_state():
    """Current live state from each provider."""
    mgr = get_manager()
    return jsonify(mgr.get_state())


@tuning_bp.route('/profiles', methods=['GET'])
def get_profiles():
    """Available system profiles with readiness status."""
    mgr = get_manager()
    return jsonify({
        'profiles': mgr.get_profiles(),
        'afterburner_guide': mgr.get_afterburner_guide(),
    })


@tuning_bp.route('/apply-profile', methods=['POST'])
def apply_profile():
    """Apply a named system profile (safety-gated)."""
    data = request.get_json()
    if not data or 'profile' not in data:
        return jsonify({'error': 'Missing profile name'}), 400

    mgr = get_manager()
    result = mgr.apply_profile(data['profile'])

    if result.get('blocked_by') == 'SAFETY_GATE':
        return jsonify(result), 403

    return jsonify(result)


@tuning_bp.route('/verify', methods=['POST'])
def verify():
    """Read-back verification of applied state."""
    mgr = get_manager()
    return jsonify(mgr.verify_state())


@tuning_bp.route('/revert', methods=['POST'])
def revert():
    """Revert to last baseline."""
    mgr = get_manager()
    return jsonify(mgr.revert())


@tuning_bp.route('/deactivate', methods=['POST'])
def deactivate():
    """Deactivate tuning — revert to baseline AND stop companion apps."""
    mgr = get_manager()
    return jsonify(mgr.deactivate_tuning())


@tuning_bp.route('/history', methods=['GET'])
def get_history():
    """Receipt log of all actions."""
    count = request.args.get('count', 20, type=int)
    mgr = get_manager()
    return jsonify({'receipts': mgr.get_history(count)})
