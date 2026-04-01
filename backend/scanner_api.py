"""
Project vulnerability scanner for Aegis.
Scans project directories for security issues: hardcoded secrets, dangerous functions,
exposed network bindings, missing input validation, sensitive files.

v2: Closed-loop remediation — suggest_fix, verify_file, resolution persistence.
"""
import os
import re
import time
import json
import sqlite3
import hashlib
from datetime import datetime
from flask import Blueprint, jsonify, request
from remediation_engine import suggest_fix as get_suggestion
import shutil

scanner_bp = Blueprint('scanner', __name__)


# ═══════════════════════════════════════════
# HARDENED FILE I/O
# ═══════════════════════════════════════════

def _safe_read_file(filepath):
    """Read a file preserving encoding metadata.
    Returns (lines: list[str], meta: dict) where meta contains:
        encoding, bom, newline_style, original_size
    Raises on failure.
    """
    original_size = os.path.getsize(filepath)

    # Detect BOM
    with open(filepath, 'rb') as f:
        raw_head = f.read(4)

    bom = ''
    encoding = 'utf-8'
    if raw_head[:3] == b'\xef\xbb\xbf':
        bom = 'utf-8-sig'
        encoding = 'utf-8-sig'
    elif raw_head[:2] == b'\xff\xfe':
        bom = 'utf-16-le'
        encoding = 'utf-16-le'
    elif raw_head[:2] == b'\xfe\xff':
        bom = 'utf-16-be'
        encoding = 'utf-16-be'

    # Read content
    with open(filepath, 'r', encoding=encoding, errors='replace') as f:
        content = f.read()

    # Detect dominant newline style
    crlf_count = content.count('\r\n')
    lf_count = content.count('\n') - crlf_count
    newline_style = '\r\n' if crlf_count > lf_count else '\n'

    lines = content.splitlines(True)  # Keep line endings

    return lines, {
        'encoding': encoding,
        'bom': bom,
        'newline_style': newline_style,
        'original_size': original_size,
    }


# ═══════════════════════════════════════════
# BACKUP CHAIN CONFIGURATION
# ═══════════════════════════════════════════
_scanner_config = {
    'backup_chain_depth': 3,  # Default: keep 3 backup levels
}

DEFAULT_BACKUP_CHAIN_DEPTH = 3
MIN_BACKUP_DEPTH = 1
MAX_BACKUP_DEPTH = 10


@scanner_bp.route('/config', methods=['GET'])
def get_scanner_config():
    """Return current scanner configuration."""
    return jsonify({
        'backup_chain_depth': _scanner_config['backup_chain_depth'],
        'min_depth': MIN_BACKUP_DEPTH,
        'max_depth': MAX_BACKUP_DEPTH,
    })


@scanner_bp.route('/config', methods=['POST'])
def set_scanner_config():
    """Update scanner configuration."""
    data = request.get_json() or {}

    if 'backup_chain_depth' in data:
        depth = data['backup_chain_depth']
        if not isinstance(depth, int) or depth < MIN_BACKUP_DEPTH or depth > MAX_BACKUP_DEPTH:
            return jsonify({
                'error': f'backup_chain_depth must be integer between {MIN_BACKUP_DEPTH} and {MAX_BACKUP_DEPTH}'
            }), 400
        _scanner_config['backup_chain_depth'] = depth

    return jsonify({
        'status': 'updated',
        'backup_chain_depth': _scanner_config['backup_chain_depth'],
    })


def _safe_write_file(filepath, lines, meta):
    """Atomic write with verified multi-level backup chain.

    Backup rotation (depth=3 example):
        .aegis.bak.2 → .aegis.bak.3 (deleted if exists, beyond depth)
        .aegis.bak.1 → .aegis.bak.2
        .aegis.bak   → .aegis.bak.1
        current file → .aegis.bak (fresh)

    Then:
        1. Write to .aegis.tmp
        2. Flush + fsync
        3. os.replace() atomically over original

    Returns dict with backup_path and chain_depth.
    """
    depth = _scanner_config.get('backup_chain_depth', DEFAULT_BACKUP_CHAIN_DEPTH)
    backup_base = filepath + '.aegis.bak'

    # Step 1: Rotate existing backup chain (highest to lowest)
    # Delete anything beyond depth
    for i in range(depth + 2, 0, -1):
        old_path = f"{backup_base}.{i}" if i > 0 else backup_base
        if i > depth and os.path.isfile(old_path):
            os.remove(old_path)

    # Rotate: .bak.N → .bak.N+1 (from highest to lowest)
    for i in range(depth - 1, 0, -1):
        src = f"{backup_base}.{i}"
        dst = f"{backup_base}.{i + 1}"
        if os.path.isfile(src):
            shutil.move(src, dst)

    # Rotate: .bak → .bak.1
    if os.path.isfile(backup_base):
        shutil.move(backup_base, f"{backup_base}.1")

    # Step 2: Create fresh backup from current file
    shutil.copy2(filepath, backup_base)

    if not os.path.isfile(backup_base):
        raise IOError(f"Backup creation failed: {backup_base} not found after copy")

    backup_size = os.path.getsize(backup_base)
    if meta['original_size'] > 0 and backup_size == 0:
        raise IOError(f"Backup verification failed: backup is 0 bytes but original was {meta['original_size']}")

    # Step 3: Write to tmp file
    tmp_path = filepath + '.aegis.tmp'
    encoding = meta.get('encoding', 'utf-8')

    with open(tmp_path, 'w', encoding=encoding, newline='') as f:
        f.writelines(lines)
        f.flush()
        os.fsync(f.fileno())

    # Step 4: Atomic replace
    os.replace(tmp_path, filepath)

    return {
        'backup_path': backup_base,
        'chain_depth': depth,
    }


# ────────────────────────────────────────
# Finding Resolution Persistence (SQLite)
# ────────────────────────────────────────
RESOLUTION_DB = os.path.join(os.path.dirname(__file__), 'aegis_resolutions.db')


def _init_resolution_db():
    """Create the resolution tracking table if it doesn't exist."""
    conn = sqlite3.connect(RESOLUTION_DB)
    conn.execute('''
        CREATE TABLE IF NOT EXISTS finding_resolutions (
            finding_hash TEXT PRIMARY KEY,
            project_path TEXT NOT NULL,
            file_path TEXT NOT NULL,
            category TEXT NOT NULL,
            title TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'OPEN',
            resolved_at TEXT,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        )
    ''')
    conn.commit()
    conn.close()


def _finding_hash(project_path, finding):
    """Deterministic hash for a finding (project + file + line + category + title)."""
    key = f"{project_path}|{finding.get('file', '')}|{finding.get('line', 0)}|{finding.get('category', '')}|{finding.get('title', '')}"
    return hashlib.sha256(key.encode()).hexdigest()[:16]


def _get_resolution(finding_hash):
    """Get resolution status for a finding."""
    conn = sqlite3.connect(RESOLUTION_DB)
    row = conn.execute(
        'SELECT status, resolved_at FROM finding_resolutions WHERE finding_hash = ?',
        (finding_hash,)
    ).fetchone()
    conn.close()
    if row:
        return {'status': row[0], 'resolved_at': row[1]}
    return None


def _set_resolution(finding_hash, project_path, finding, status):
    """Set or update resolution status for a finding."""
    now = datetime.now().isoformat()
    conn = sqlite3.connect(RESOLUTION_DB)
    conn.execute('''
        INSERT INTO finding_resolutions (finding_hash, project_path, file_path, category, title, status, resolved_at, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(finding_hash) DO UPDATE SET
            status = excluded.status,
            resolved_at = excluded.resolved_at,
            updated_at = excluded.updated_at
    ''', (
        finding_hash, project_path,
        finding.get('file', ''), finding.get('category', ''), finding.get('title', ''),
        status,
        now if status in ('FIXED', 'IGNORED') else None,
        now, now
    ))
    conn.commit()
    conn.close()


# Initialize DB on module load
_init_resolution_db()

# ────────────────────────────────────────
# Patterns
# ────────────────────────────────────────
SECRET_PATTERNS = [
    (re.compile(r'(?:api[_-]?key|apikey)\s*[:=]\s*["\']([A-Za-z0-9_\-]{16,})["\']', re.I), 'API Key'),
    (re.compile(r'(?:secret|password|passwd|pwd)\s*[:=]\s*["\']([^"\']{8,})["\']', re.I), 'Password/Secret'),
    (re.compile(r'(?:token|bearer)\s*[:=]\s*["\']([A-Za-z0-9_\-\.]{20,})["\']', re.I), 'Token'),
    (re.compile(r'(?:aws_access_key_id|aws_secret)\s*[:=]\s*["\']([A-Z0-9]{16,})["\']', re.I), 'AWS Key'),
    (re.compile(r'(?:private[_-]?key)\s*[:=]\s*["\']([^"\']{20,})["\']', re.I), 'Private Key'),
    (re.compile(r'-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----', re.I), 'Private Key Block'),
    (re.compile(r'(?:DATABASE_URL|MONGO_URI|REDIS_URL)\s*[:=]\s*["\']([^"\']+)["\']', re.I), 'Database URI'),
]

DANGEROUS_FUNCTIONS = [
    (re.compile(r'\beval\s*\('), 'eval()', '.py'),
    (re.compile(r'\bexec\s*\('), 'exec()', '.py'),
    (re.compile(r'\b__import__\s*\('), '__import__()', '.py'),
    (re.compile(r'\bsubprocess\.call\s*\(.*shell\s*=\s*True'), 'subprocess shell=True', '.py'),
    (re.compile(r'\bos\.system\s*\('), 'os.system()', '.py'),
    (re.compile(r'\beval\s*\('), 'eval()', '.js'),
    (re.compile(r'\bnew\s+Function\s*\('), 'new Function()', '.js'),
    (re.compile(r'innerHTML\s*='), 'innerHTML assignment', '.js'),
    (re.compile(r'document\.write\s*\('), 'document.write()', '.js'),
]

BINDING_PATTERNS = [
    (re.compile(r'\.listen\s*\(\s*["\']?0\.0\.0\.0["\']?'), 'Binding to 0.0.0.0'),
    (re.compile(r'host\s*[:=]\s*["\']0\.0\.0\.0["\']'), 'Host set to 0.0.0.0'),
    (re.compile(r'CORS\s*\(\s*\w+\s*\)'), 'CORS enabled (unrestricted)'),
    (re.compile(r'Access-Control-Allow-Origin.*\*'), 'CORS wildcard origin'),
]

SENSITIVE_FILES = {'.env', '.env.local', '.env.production', 'id_rsa', 'id_ed25519',
                   '.htpasswd', 'credentials.json', 'service-account.json'}

EXCLUDE_DIRS = {'node_modules', '.git', 'dist', 'build', '__pycache__', '.venv',
                'venv', '.next', 'out', 'coverage', '.pytest_cache', 'target',
                '.cargo', 'pkg', 'debug', 'release'}

SCAN_EXTENSIONS = {'.py', '.js', '.ts', '.jsx', '.tsx', '.env', '.json', '.yml', '.yaml', '.toml', '.cfg', '.ini'}


def scan_project(project_path):
    """Scan a project directory and return structured findings."""
    findings = []
    files_scanned = 0
    start = time.time()

    if not os.path.isdir(project_path):
        return {'error': f'Not a directory: {project_path}'}

    for root, dirs, files in os.walk(project_path):
        dirs[:] = [d for d in dirs if d not in EXCLUDE_DIRS]

        for filename in files:
            filepath = os.path.join(root, filename)
            rel_path = os.path.relpath(filepath, project_path)
            _, ext = os.path.splitext(filename)
            ext = ext.lower()

            # Check sensitive files
            if filename.lower() in SENSITIVE_FILES:
                findings.append({
                    'severity': 'HIGH',
                    'category': 'Sensitive File',
                    'file': rel_path,
                    'line': 0,
                    'title': f'Sensitive file detected: {filename}',
                    'detail': 'This file may contain credentials or private keys.',
                })

            if ext not in SCAN_EXTENSIONS:
                continue

            try:
                with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read(256_000)  # Cap at 256KB per file
            except Exception:
                continue

            files_scanned += 1
            lines = content.splitlines()

            for i, line in enumerate(lines):
                line_num = i + 1

                # Secret detection
                for pattern, secret_type in SECRET_PATTERNS:
                    if pattern.search(line):
                        # Skip false positives in test files, examples, lockfiles
                        if any(x in rel_path.lower() for x in ['test', 'example', 'mock', 'fixture', 'package-lock', 'yarn.lock']):
                            continue
                        findings.append({
                            'severity': 'CRITICAL',
                            'category': 'Hardcoded Secret',
                            'file': rel_path,
                            'line': line_num,
                            'title': f'{secret_type} detected',
                            'detail': f'Line {line_num}: potential {secret_type.lower()} in source code',
                        })

                # Dangerous functions
                for pattern, func_name, target_ext in DANGEROUS_FUNCTIONS:
                    if ext == target_ext and pattern.search(line):
                        # Skip comments
                        stripped = line.strip()
                        if stripped.startswith('#') or stripped.startswith('//'):
                            continue
                        findings.append({
                            'severity': 'MEDIUM',
                            'category': 'Dangerous Function',
                            'file': rel_path,
                            'line': line_num,
                            'title': f'{func_name} usage detected',
                            'detail': f'Line {line_num}: {func_name} can lead to code injection',
                        })

                # Network binding
                for pattern, msg in BINDING_PATTERNS:
                    if pattern.search(line):
                        findings.append({
                            'severity': 'MEDIUM',
                            'category': 'Exposed Binding',
                            'file': rel_path,
                            'line': line_num,
                            'title': msg,
                            'detail': f'Line {line_num}: {msg.lower()} — potential network exposure',
                        })

    elapsed_ms = int((time.time() - start) * 1000)

    # Severity counts
    sev_counts = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
    for f in findings:
        sev_counts[f['severity']] = sev_counts.get(f['severity'], 0) + 1

    return {
        'project_path': project_path,
        'files_scanned': files_scanned,
        'total_findings': len(findings),
        'severity_counts': sev_counts,
        'findings': findings[:100],  # Cap at 100 findings for UI performance
        'scan_time_ms': elapsed_ms,
    }


@scanner_bp.route('/scan', methods=['POST'])
def scan_project_endpoint():
    data = request.get_json()
    project_path = data.get('path', '')

    if not project_path or not os.path.isdir(project_path):
        return jsonify({'error': 'Invalid project path'}), 400

    # Safety: only allow scanning paths under known project roots
    allowed_roots = [
        r'C:\Veritas_Lab',
        r'C:\Users\rlope\OneDrive\Desktop\AI WorK',
        r'C:\Users\rlope\OneDrive\Desktop',
    ]
    path_ok = any(os.path.normpath(project_path).startswith(os.path.normpath(r)) for r in allowed_roots)
    if not path_ok:
        return jsonify({'error': 'Path not in allowed scan roots'}), 403

    result = scan_project(project_path)
    return jsonify(result)


@scanner_bp.route('/quarantine', methods=['POST'])
def quarantine_file():
    """Move a suspicious file to quarantine directory."""
    import shutil
    import json
    from datetime import datetime

    data = request.get_json()
    file_path = data.get('path', '')

    if not file_path or not os.path.isfile(file_path):
        return jsonify({'error': 'File not found'}), 404

    # Safety: only allow quarantining from known roots
    allowed_roots = [
        r'C:\Veritas_Lab',
        r'C:\Users\rlope\OneDrive\Desktop',
    ]
    path_ok = any(os.path.normpath(file_path).startswith(os.path.normpath(r)) for r in allowed_roots)
    if not path_ok:
        return jsonify({'error': 'Path not in allowed roots'}), 403

    # Never quarantine system files or our own app
    protected = ['app.py', 'main.js', 'preload.js', 'renderer.js', 'index.html', 'style.css']
    if os.path.basename(file_path) in protected:
        return jsonify({'error': 'Cannot quarantine protected application file'}), 403

    quarantine_dir = r'C:\Veritas_Lab\aegis-home-base\quarantine'
    os.makedirs(quarantine_dir, exist_ok=True)

    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    safe_name = os.path.basename(file_path).replace(' ', '_')
    dest = os.path.join(quarantine_dir, f'{timestamp}_{safe_name}')

    try:
        shutil.move(file_path, dest)

        # Write manifest entry
        manifest_path = os.path.join(quarantine_dir, 'manifest.json')
        manifest = []
        if os.path.isfile(manifest_path):
            with open(manifest_path, 'r') as f:
                manifest = json.load(f)

        manifest.append({
            'original_path': file_path,
            'quarantine_path': dest,
            'timestamp': datetime.now().isoformat(),
            'reason': data.get('reason', 'User-initiated quarantine from Aegis'),
        })

        with open(manifest_path, 'w') as f:
            json.dump(manifest, f, indent=2)

        return jsonify({'status': 'quarantined', 'destination': dest})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


# ────────────────────────────────────────
# REMEDIATION ENDPOINTS (Scan → Fix → Verify)
# ────────────────────────────────────────

@scanner_bp.route('/suggest_fix', methods=['POST'])
def suggest_fix_endpoint():
    """Return a deterministic remediation suggestion for a finding."""
    data = request.get_json()
    if not data:
        return jsonify({'error': 'No finding provided'}), 400

    finding = data.get('finding', data)
    suggestion = get_suggestion(finding)
    return jsonify(suggestion)


@scanner_bp.route('/verify_file', methods=['POST'])
def verify_file_endpoint():
    """Re-scan a single file to check if a specific finding is still present.
    This is the VERIFY phase of the closed-loop remediation system.
    """
    data = request.get_json()
    project_path = data.get('project_path', '')
    file_rel = data.get('file', '')
    category = data.get('category', '')
    finding_hash = data.get('finding_hash', '')

    if not project_path or not file_rel:
        return jsonify({'error': 'Missing project_path or file'}), 400

    filepath = os.path.join(project_path, file_rel)
    if not os.path.isfile(filepath):
        # File was deleted or moved — finding is resolved
        if finding_hash:
            _set_resolution(finding_hash, project_path,
                            {'file': file_rel, 'category': category, 'title': ''},
                            'FIXED')
        return jsonify({
            'status': 'RESOLVED',
            'reason': 'File no longer exists',
            'findings_remaining': 0,
        })

    # Scan just this one file
    try:
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read(256_000)
    except Exception as e:
        return jsonify({'error': f'Cannot read file: {str(e)}'}), 500

    _, ext = os.path.splitext(filepath)
    ext = ext.lower()
    lines = content.splitlines()

    # Run the same detection rules against this single file
    findings_in_file = []
    for i, line in enumerate(lines):
        line_num = i + 1

        for pattern, secret_type in SECRET_PATTERNS:
            if pattern.search(line):
                if any(x in file_rel.lower() for x in ['test', 'example', 'mock', 'fixture', 'package-lock', 'yarn.lock']):
                    continue
                findings_in_file.append({
                    'severity': 'CRITICAL',
                    'category': 'Hardcoded Secret',
                    'file': file_rel,
                    'line': line_num,
                    'title': f'{secret_type} detected',
                })

        for pattern, func_name, target_ext in DANGEROUS_FUNCTIONS:
            if ext == target_ext and pattern.search(line):
                stripped = line.strip()
                if stripped.startswith('#') or stripped.startswith('//'):
                    continue
                findings_in_file.append({
                    'severity': 'MEDIUM',
                    'category': 'Dangerous Function',
                    'file': file_rel,
                    'line': line_num,
                    'title': f'{func_name} usage detected',
                })

        for pattern, msg in BINDING_PATTERNS:
            if pattern.search(line):
                findings_in_file.append({
                    'severity': 'MEDIUM',
                    'category': 'Exposed Binding',
                    'file': file_rel,
                    'line': line_num,
                    'title': msg,
                })

    # Filter to only findings matching the requested category (if specified)
    if category:
        matching = [f for f in findings_in_file if f['category'] == category]
    else:
        matching = findings_in_file

    resolved = len(matching) == 0

    # Update persistence
    if finding_hash:
        _set_resolution(finding_hash, project_path,
                        {'file': file_rel, 'category': category, 'title': ''},
                        'FIXED' if resolved else 'OPEN')

    return jsonify({
        'status': 'RESOLVED' if resolved else 'STILL_PRESENT',
        'findings_remaining': len(matching),
        'findings': matching,
        'file': file_rel,
        'verified_at': datetime.now().isoformat(),
    })


@scanner_bp.route('/resolution', methods=['POST'])
def set_resolution_endpoint():
    """Set finding resolution status (OPEN, FIXED, IGNORED)."""
    data = request.get_json()
    finding_hash = data.get('finding_hash', '')
    project_path = data.get('project_path', '')
    status = data.get('status', 'OPEN')

    if not finding_hash:
        return jsonify({'error': 'Missing finding_hash'}), 400
    if status not in ('OPEN', 'FIXED', 'IGNORED'):
        return jsonify({'error': f'Invalid status: {status}'}), 400

    finding = {
        'file': data.get('file', ''),
        'category': data.get('category', ''),
        'title': data.get('title', ''),
    }
    _set_resolution(finding_hash, project_path, finding, status)

    return jsonify({'status': status, 'finding_hash': finding_hash})


@scanner_bp.route('/resolutions', methods=['GET'])
def get_resolutions_endpoint():
    """Get all persisted resolution states for a project."""
    project_path = request.args.get('project_path', '')
    if not project_path:
        return jsonify({'error': 'Missing project_path'}), 400

    conn = sqlite3.connect(RESOLUTION_DB)
    rows = conn.execute(
        'SELECT finding_hash, file_path, category, title, status, resolved_at FROM finding_resolutions WHERE project_path = ?',
        (project_path,)
    ).fetchall()
    conn.close()

    resolutions = {}
    for row in rows:
        resolutions[row[0]] = {
            'file': row[1],
            'category': row[2],
            'title': row[3],
            'status': row[4],
            'resolved_at': row[5],
        }

    return jsonify(resolutions)


@scanner_bp.route('/read_file', methods=['POST'])
def read_file_endpoint():
    """Read file content around a specific line for inline editing.
    Returns a context window with line numbers.
    """
    data = request.get_json()
    project_path = data.get('project_path', '')
    file_rel = data.get('file', '')
    target_line = data.get('line', 1)
    context = data.get('context', 15)  # lines above/below

    if not project_path or not file_rel:
        return jsonify({'error': 'Missing project_path or file'}), 400

    filepath = os.path.join(project_path, file_rel)
    if not os.path.isfile(filepath):
        return jsonify({'error': f'File not found: {file_rel}'}), 404

    try:
        with open(filepath, 'r', encoding='utf-8', errors='replace') as f:
            all_lines = f.readlines()
    except Exception as e:
        return jsonify({'error': f'Cannot read file: {str(e)}'}), 500

    total_lines = len(all_lines)
    start = max(0, target_line - 1 - context)
    end = min(total_lines, target_line + context)

    lines = []
    for i in range(start, end):
        lines.append({
            'num': i + 1,
            'text': all_lines[i].rstrip('\n').rstrip('\r'),
            'is_target': (i + 1) == target_line,
        })

    return jsonify({
        'file': file_rel,
        'total_lines': total_lines,
        'start_line': start + 1,
        'end_line': end,
        'target_line': target_line,
        'lines': lines,
        'filepath': filepath,
    })


@scanner_bp.route('/write_file', methods=['POST'])
def write_file_endpoint():
    """Write edited content back to a file.
    Creates .aegis.bak backup. Returns line-level diff of changes.
    """
    data = request.get_json()
    project_path = data.get('project_path', '')
    file_rel = data.get('file', '')
    edited_lines = data.get('lines', [])  # [{num, text}, ...]

    if not project_path or not file_rel:
        return jsonify({'error': 'Missing project_path or file'}), 400
    if not edited_lines:
        return jsonify({'error': 'No edited content provided'}), 400

    filepath = os.path.join(project_path, file_rel)
    if not os.path.isfile(filepath):
        return jsonify({'error': f'File not found: {file_rel}'}), 404

    try:
        # Read with encoding detection
        original_lines, meta = _safe_read_file(filepath)
        nl = meta['newline_style']

        # Compute diff before applying
        diff = []
        new_lines = list(original_lines)
        for edited in edited_lines:
            idx = edited['num'] - 1
            if 0 <= idx < len(new_lines):
                old_text = new_lines[idx].rstrip('\n').rstrip('\r')
                new_text = edited['text']
                if old_text != new_text:
                    diff.append({
                        'line': edited['num'],
                        'old': old_text,
                        'new': new_text,
                    })
                new_lines[idx] = edited['text'] + nl

        # Atomic write with verified backup chain
        write_result = _safe_write_file(filepath, new_lines, meta)

        return jsonify({
            'status': 'saved',
            'file': file_rel,
            'backup': os.path.basename(write_result['backup_path']),
            'backup_chain_depth': write_result['chain_depth'],
            'lines_modified': len(diff),
            'diff': diff,
            'saved_at': datetime.now().isoformat(),
        })

    except Exception as e:
        return jsonify({'error': f'Write failed: {str(e)}'}), 500


@scanner_bp.route('/preview_diff', methods=['POST'])
def preview_diff_endpoint():
    """Compute diff without saving. For patch preview before commit."""
    data = request.get_json()
    project_path = data.get('project_path', '')
    file_rel = data.get('file', '')
    edited_lines = data.get('lines', [])

    if not project_path or not file_rel:
        return jsonify({'error': 'Missing project_path or file'}), 400

    filepath = os.path.join(project_path, file_rel)
    if not os.path.isfile(filepath):
        return jsonify({'error': f'File not found: {file_rel}'}), 404

    try:
        with open(filepath, 'r', encoding='utf-8', errors='replace') as f:
            original_lines = f.readlines()

        diff = []
        for edited in edited_lines:
            idx = edited['num'] - 1
            if 0 <= idx < len(original_lines):
                old_text = original_lines[idx].rstrip('\n').rstrip('\r')
                new_text = edited['text']
                if old_text != new_text:
                    diff.append({
                        'line': edited['num'],
                        'old': old_text,
                        'new': new_text,
                    })

        return jsonify({
            'diff': diff,
            'total_changes': len(diff),
        })

    except Exception as e:
        return jsonify({'error': str(e)}), 500


@scanner_bp.route('/apply_fix', methods=['POST'])
def apply_fix_endpoint():
    """Apply a deterministic fix from the remediation engine.
    Only works for high-confidence rules (>= 0.85).
    Reads the target line, applies the pattern substitution, returns diff preview.
    If confirm=True, writes the file.
    """
    data = request.get_json()
    project_path = data.get('project_path', '')
    file_rel = data.get('file', '')
    target_line = data.get('line', 0)
    category = data.get('category', '')
    title = data.get('title', '')
    confirm = data.get('confirm', False)

    if not project_path or not file_rel or not target_line:
        return jsonify({'error': 'Missing required fields'}), 400

    filepath = os.path.join(project_path, file_rel)
    if not os.path.isfile(filepath):
        return jsonify({'error': f'File not found: {file_rel}'}), 404

    # Get the remediation suggestion
    from remediation_engine import suggest_fix
    suggestion = suggest_fix({'category': category, 'title': title})

    if not suggestion.get('matched') or suggestion.get('confidence', 0) < 0.85:
        return jsonify({
            'error': 'No high-confidence auto-fix available for this finding.',
            'confidence': suggestion.get('confidence', 0),
        }), 400

    try:
        lines, meta = _safe_read_file(filepath)
        nl = meta['newline_style']

        idx = target_line - 1
        if idx < 0 or idx >= len(lines):
            return jsonify({'error': f'Line {target_line} out of range'}), 400

        old_line = lines[idx].rstrip('\n').rstrip('\r')

        # Apply deterministic pattern-based fixes
        new_line = _apply_pattern_fix(old_line, category, title)

        if new_line == old_line:
            return jsonify({
                'status': 'no_change',
                'message': 'Pattern did not match the target line. Manual edit recommended.',
                'old_line': old_line,
            })

        diff = [{'line': target_line, 'old': old_line, 'new': new_line}]

        if not confirm:
            # Preview only
            return jsonify({
                'status': 'preview',
                'diff': diff,
                'confidence': suggestion['confidence'],
            })

        # Atomic write with verified backup chain
        lines[idx] = new_line + nl
        write_result = _safe_write_file(filepath, lines, meta)

        return jsonify({
            'status': 'applied',
            'diff': diff,
            'backup': os.path.basename(write_result['backup_path']),
            'backup_chain_depth': write_result['chain_depth'],
            'confidence': suggestion['confidence'],
            'saved_at': datetime.now().isoformat(),
        })

    except Exception as e:
        return jsonify({'error': f'Apply fix failed: {str(e)}'}), 500


def _apply_pattern_fix(line, category, title):
    """Apply deterministic regex-based line transforms.
    Returns the fixed line, or unchanged line if no pattern matches.
    """
    title_lower = title.lower()

    # ── CORS wildcard → restricted ──
    if 'cors' in title_lower:
        # CORS(app) → CORS(app, origins=["https://localhost"])
        line = re.sub(
            r'CORS\s*\(\s*app\s*\)',
            'CORS(app, origins=["http://127.0.0.1"])',
            line
        )
        return line

    # ── 0.0.0.0 → 127.0.0.1 ──
    if '0.0.0.0' in title_lower or '0.0.0.0' in line:
        line = line.replace('0.0.0.0', '127.0.0.1')
        return line

    # ── innerHTML → textContent ──
    if 'innerhtml' in title_lower:
        line = line.replace('.innerHTML', '.textContent')
        return line

    # ── document.write → createElement ──
    if 'document.write' in title_lower:
        line = re.sub(r'document\.write\s*\(', '// REMOVED: document.write(', line)
        return line

    # ── eval() → ast.literal_eval() ──
    if title_lower.startswith('eval'):
        line = line.replace('eval(', 'ast.literal_eval(')
        return line

    # ── os.system() → subprocess.run() ──
    if 'os.system' in title_lower:
        line = line.replace('os.system(', 'subprocess.run(')
        return line

    # ── debug=True → debug=False ──
    if 'debug' in line.lower():
        line = re.sub(r'debug\s*=\s*True', 'debug=False', line)

    # ── Hardcoded secrets: comment out the line with warning ──
    if category == 'Hardcoded Secret':
        stripped = line.lstrip()
        indent = line[:len(line) - len(stripped)]
        if stripped and not stripped.startswith('#') and not stripped.startswith('//'):
            comment_char = '#' if any(line.endswith(ext) for ext in ['.py']) else '//'
            # Default to # since scanner mostly hits Python
            line = f"{indent}# FIXME [AEGIS]: Move to environment variable\n{indent}# {stripped}"
            return line

    return line


@scanner_bp.route('/batch_fix', methods=['POST'])
def batch_fix_endpoint():
    """Batch-apply deterministic fixes to all eligible findings in a project.
    Only touches findings with remediation confidence >= 0.85.
    Groups changes by file, creates one .aegis.bak backup per file.

    Args (JSON body):
        project_path: str
        findings: list of {file, line, category, title, _hash}
        confirm: bool (False = preview only, True = apply)

    Returns:
        eligible: int (findings with auto-fix available)
        skipped: int (findings without auto-fix)
        changes: list of {file, line, category, title, old, new}
        files_modified: int (distinct files)
        status: 'preview' | 'applied'
    """
    data = request.get_json()
    project_path = data.get('project_path', '')
    findings_list = data.get('findings', [])
    confirm = data.get('confirm', False)

    if not project_path:
        return jsonify({'error': 'Missing project_path'}), 400
    if not findings_list:
        return jsonify({'error': 'No findings provided'}), 400

    from remediation_engine import suggest_fix

    # Phase 1: Classify eligible findings
    eligible = []
    skipped = 0

    for f in findings_list:
        suggestion = suggest_fix({'category': f.get('category', ''), 'title': f.get('title', '')})
        if suggestion.get('matched') and suggestion.get('confidence', 0) >= 0.85:
            eligible.append({
                'file': f.get('file', ''),
                'line': f.get('line', 0),
                'category': f.get('category', ''),
                'title': f.get('title', ''),
                '_hash': f.get('_hash', ''),
                'confidence': suggestion['confidence'],
            })
        else:
            skipped += 1

    if not eligible:
        return jsonify({
            'status': 'no_eligible',
            'eligible': 0,
            'skipped': skipped,
            'message': 'No findings have high-confidence auto-fix patterns.',
        })

    # Phase 2: Group by file, read each file, compute diffs
    from collections import defaultdict
    by_file = defaultdict(list)
    for e in eligible:
        by_file[e['file']].append(e)

    changes = []
    file_line_cache = {}  # file -> list of lines (read once)

    file_meta_cache = {}  # file -> meta from _safe_read_file

    for file_rel, file_findings in by_file.items():
        filepath = os.path.join(project_path, file_rel)
        if not os.path.isfile(filepath):
            continue

        # Read file with encoding detection (cached)
        if file_rel not in file_line_cache:
            try:
                lines_read, meta = _safe_read_file(filepath)
                file_line_cache[file_rel] = lines_read
                file_meta_cache[file_rel] = meta
            except Exception:
                continue

        lines = list(file_line_cache[file_rel])  # copy for mutation
        nl = file_meta_cache.get(file_rel, {}).get('newline_style', '\n')

        for finding in file_findings:
            idx = finding['line'] - 1
            if idx < 0 or idx >= len(lines):
                continue

            old_line = lines[idx].rstrip('\n').rstrip('\r')
            new_line = _apply_pattern_fix(old_line, finding['category'], finding['title'])

            if new_line != old_line:
                changes.append({
                    'file': file_rel,
                    'line': finding['line'],
                    'category': finding['category'],
                    'title': finding['title'],
                    'old': old_line,
                    'new': new_line,
                    '_hash': finding['_hash'],
                })
                # Update in-memory for subsequent fixes in same file
                lines[idx] = new_line + nl

        # Store mutated lines for write phase
        file_line_cache[file_rel] = lines

    if not confirm:
        return jsonify({
            'status': 'preview',
            'eligible': len(eligible),
            'skipped': skipped,
            'changes': changes,
            'files_affected': len(by_file),
        })

    # Phase 3: Apply all changes — atomic writes with verified backups
    files_written = set()
    backups_created = []
    failures = []

    for file_rel, mutated_lines in file_line_cache.items():
        filepath = os.path.join(project_path, file_rel)
        if not os.path.isfile(filepath):
            continue

        # Only write files that had actual changes
        if not any(c['file'] == file_rel for c in changes):
            continue

        meta = file_meta_cache.get(file_rel, {
            'encoding': 'utf-8', 'bom': '', 'newline_style': '\n',
            'original_size': os.path.getsize(filepath),
        })

        try:
            write_result = _safe_write_file(filepath, mutated_lines, meta)
            files_written.add(file_rel)
            backups_created.append(os.path.basename(write_result['backup_path']))
        except Exception as exc:
            failures.append({'file': file_rel, 'error': str(exc)})
            print(f"[AEGIS BATCH] Failed to write {file_rel}: {exc}")

    return jsonify({
        'status': 'applied',
        'eligible': len(eligible),
        'skipped': skipped,
        'changes': changes,
        'files_modified': len(files_written),
        'files_list': sorted(files_written),
        'backups_created': backups_created,
        'failures': failures,
        'lines_modified': len(changes),
        'saved_at': datetime.now().isoformat(),
    })
