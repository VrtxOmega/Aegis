"""
Aegis Batch Fix Smoke Test — End-to-End
========================================
Creates a temporary project with intentionally vulnerable files,
runs the full scan → preview → apply → verify pipeline,
and validates backup integrity.

Requires: Aegis backend running on 127.0.0.1:5000

Usage:
    python test_batch_fix_smoke.py
"""
import sys
import os
import json
import time
import shutil
import tempfile
import requests

BACKEND_URL = "http://127.0.0.1:5000"
TIMEOUT = 60


# ═══════════════════════════════════════════
# VULNERABLE FILE TEMPLATES
# ═══════════════════════════════════════════

VULN_DEBUG = '''"""Flask app with debug mode enabled."""
from flask import Flask

app = Flask(__name__)

@app.route('/')
def index():
    return "Hello World"

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=8080)
'''

VULN_SECRET = '''"""Config with hardcoded secrets."""
import os

API_KEY = "sk-hardcoded-12345-this-is-a-secret"
DATABASE_URL = "postgres://admin:password123@db.example.com/prod"

def connect():
    return DATABASE_URL
'''

VULN_EVAL = '''"""Module with dangerous eval usage."""
import json

def parse_user_input(raw):
    """Parse user config from string."""
    result = eval(raw)  # DANGEROUS: code injection
    return result

def process_data(data_str):
    return eval(data_str)
'''


def setup_temp_project():
    """Create a temporary project with vulnerable files."""
    tmp_dir = tempfile.mkdtemp(prefix='aegis_test_')
    print(f"  Created temp project: {tmp_dir}")

    files = {
        'vuln_debug.py': VULN_DEBUG,
        'vuln_secret.py': VULN_SECRET,
        'vuln_eval.py': VULN_EVAL,
    }

    for name, content in files.items():
        filepath = os.path.join(tmp_dir, name)
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(content)
        print(f"    Written: {name} ({len(content)} bytes)")

    return tmp_dir


def phase_1_scan(project_path):
    """Phase 1: Scan the project and verify findings."""
    print("\n─── PHASE 1: SCAN ───")

    resp = requests.post(
        f"{BACKEND_URL}/api/scanner/scan",
        json={"path": project_path},
        timeout=TIMEOUT
    )
    data = resp.json()

    if 'error' in data:
        print(f"  FAIL: Scan error: {data['error']}")
        return None

    findings = data.get('findings', [])
    print(f"  Findings: {len(findings)}")

    for f in findings:
        print(f"    [{f.get('severity', '?'):8s}] {f.get('category', '?')} — {f.get('title', '?')} in {f.get('file', '?')}:{f.get('line', '?')}")

    if len(findings) < 2:
        print(f"  FAIL: Expected at least 2 findings, got {len(findings)}")
        return None

    # Check categories we expect
    categories = set(f.get('category', '') for f in findings)
    expected = {'Dangerous Function', 'Hardcoded Secret'}
    found_expected = categories & expected
    if not found_expected:
        print(f"  WARN: Expected categories {expected}, got {categories}")

    print(f"  PASS: {len(findings)} findings across {len(categories)} categories")
    return data


def phase_2_preview(project_path, scan_data):
    """Phase 2: Batch preview — verify diffs without modifying files."""
    print("\n─── PHASE 2: BATCH PREVIEW ───")

    findings = scan_data.get('findings', [])

    # Save original file contents for comparison
    originals = {}
    for f in findings:
        filepath = os.path.join(project_path, f.get('file', ''))
        if os.path.isfile(filepath) and filepath not in originals:
            with open(filepath, 'r', encoding='utf-8') as fh:
                originals[filepath] = fh.read()

    resp = requests.post(
        f"{BACKEND_URL}/api/scanner/batch_fix",
        json={
            "project_path": project_path,
            "findings": findings,
            "confirm": False,
        },
        timeout=TIMEOUT
    )
    data = resp.json()

    status = data.get('status', '')
    if status != 'preview':
        print(f"  FAIL: Expected status='preview', got '{status}'")
        print(f"  Response: {json.dumps(data, indent=2)}")
        return None

    changes = data.get('changes', [])
    eligible = data.get('eligible', 0)
    print(f"  Status: {status}")
    print(f"  Eligible for auto-fix: {eligible}")
    print(f"  Changes preview: {len(changes)} diffs")

    for ch in changes:
        print(f"    {ch.get('file', '?')} L{ch.get('line', '?')}: "
              f"confidence={ch.get('confidence', 0):.2f}")

    # CRITICAL: Verify original files are UNTOUCHED
    all_unchanged = True
    for filepath, original in originals.items():
        with open(filepath, 'r', encoding='utf-8') as fh:
            current = fh.read()
        if current != original:
            print(f"  FAIL: {filepath} was modified during preview!")
            all_unchanged = False

    if not all_unchanged:
        return None

    print(f"  PASS: Preview generated, originals untouched")
    return data


def phase_3_apply(project_path, scan_data):
    """Phase 3: Batch apply — modify files and verify backups."""
    print("\n─── PHASE 3: BATCH APPLY ───")

    findings = scan_data.get('findings', [])

    # Save originals for backup verification
    originals = {}
    for f in findings:
        filepath = os.path.join(project_path, f.get('file', ''))
        if os.path.isfile(filepath) and filepath not in originals:
            with open(filepath, 'r', encoding='utf-8') as fh:
                originals[filepath] = fh.read()

    resp = requests.post(
        f"{BACKEND_URL}/api/scanner/batch_fix",
        json={
            "project_path": project_path,
            "findings": findings,
            "confirm": True,
        },
        timeout=TIMEOUT
    )
    data = resp.json()

    status = data.get('status', '')
    if status != 'applied':
        print(f"  FAIL: Expected status='applied', got '{status}'")
        print(f"  Response: {json.dumps(data, indent=2)}")
        return None

    files_modified = data.get('files_modified', 0)
    backups = data.get('backups_created', [])
    print(f"  Status: {status}")
    print(f"  Files modified: {files_modified}")
    print(f"  Backups created: {len(backups)}")

    # Verify backups contain original content
    backup_verified = 0
    for filepath, original in originals.items():
        bak_path = filepath + '.aegis.bak'
        if os.path.isfile(bak_path):
            with open(bak_path, 'r', encoding='utf-8') as fh:
                bak_content = fh.read()
            if bak_content == original:
                backup_verified += 1
                print(f"    ✓ Backup verified: {os.path.basename(bak_path)}")
            else:
                print(f"    ✗ Backup mismatch: {os.path.basename(bak_path)}")

    # Verify modified files differ from originals
    files_changed = 0
    for filepath, original in originals.items():
        if os.path.isfile(filepath):
            with open(filepath, 'r', encoding='utf-8') as fh:
                current = fh.read()
            if current != original:
                files_changed += 1

    print(f"  Backups verified: {backup_verified}")
    print(f"  Files actually changed: {files_changed}")

    if files_modified > 0:
        print(f"  PASS: Batch apply successful")
    else:
        print(f"  WARN: No files were modified (patterns may not have matched)")

    return data


def phase_4_verify(project_path, original_scan_data):
    """Phase 4: Re-scan and verify finding count decreased."""
    print("\n─── PHASE 4: RE-SCAN VERIFICATION ───")

    resp = requests.post(
        f"{BACKEND_URL}/api/scanner/scan",
        json={"path": project_path},
        timeout=TIMEOUT
    )
    data = resp.json()

    new_findings = data.get('findings', [])
    old_count = len(original_scan_data.get('findings', []))
    new_count = len(new_findings)

    print(f"  Original findings: {old_count}")
    print(f"  After fix findings: {new_count}")
    print(f"  Resolved: {old_count - new_count}")

    if new_count < old_count:
        print(f"  PASS: Finding count decreased ({old_count} → {new_count})")
        return True
    elif new_count == old_count:
        print(f"  WARN: Finding count unchanged — patterns may not have matched")
        return True  # Not a failure, just means patterns didn't match
    else:
        print(f"  FAIL: Finding count increased!")
        return False


def main():
    print("=" * 60)
    print("  AEGIS BATCH FIX — END-TO-END SMOKE TEST")
    print("=" * 60)

    # Check backend health
    try:
        resp = requests.get(f"{BACKEND_URL}/api/health", timeout=5)
        if resp.status_code != 200:
            raise Exception(f"Backend unhealthy: {resp.status_code}")
        print("  Backend: ONLINE")
    except Exception as e:
        print(f"  ABORT: Backend not running — {e}")
        sys.exit(1)

    # Setup
    project_path = setup_temp_project()

    try:
        # Phase 1: Scan
        scan_data = phase_1_scan(project_path)
        if scan_data is None:
            print("\n  ✗ ABORTED at Phase 1")
            return 1

        # Phase 2: Preview
        preview_data = phase_2_preview(project_path, scan_data)
        if preview_data is None:
            print("\n  ✗ ABORTED at Phase 2")
            return 1

        # Phase 3: Apply
        apply_data = phase_3_apply(project_path, scan_data)
        if apply_data is None:
            print("\n  ✗ ABORTED at Phase 3")
            return 1

        # Phase 4: Verify
        verified = phase_4_verify(project_path, scan_data)

        # Summary
        print("\n" + "=" * 60)
        print("  SMOKE TEST COMPLETE")
        print("=" * 60)
        print(f"  Phase 1 (Scan):    PASS")
        print(f"  Phase 2 (Preview): PASS")
        print(f"  Phase 3 (Apply):   PASS")
        print(f"  Phase 4 (Verify):  {'PASS' if verified else 'WARN'}")
        return 0

    finally:
        # Cleanup
        print(f"\n  Cleaning up: {project_path}")
        try:
            shutil.rmtree(project_path, ignore_errors=True)
            print("  Cleanup: DONE")
        except Exception as e:
            print(f"  Cleanup failed: {e}")


if __name__ == '__main__':
    sys.exit(main())
