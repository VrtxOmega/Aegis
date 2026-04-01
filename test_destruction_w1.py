"""
AEGIS PROTECT — DESTRUCTION CAMPAIGN WAVE 1
============================================
Tests how the system FAILS, not how it works.

Attack Surfaces:
  A. HTTP/API — flood, race, malform, starve
  B. Scan concurrency — mutex integrity, zombie scans
  C. AI/Ollama — prompt injection, payload bombs
  D. Defense state — rapid toggle, orphan listeners
  E. Resource exhaustion — thread leak, connection leak

Each test is designed to expose one failure mode.
Exit code 0 if no crashes/hangs. Results graded:
  SURVIVED — system handled attack gracefully
  DEGRADED — system slow but recovered
  VULNERABLE — system crashed, hung, or returned incorrect data
"""
import os
import sys
import time
import json
import threading
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime

BASE = 'http://127.0.0.1:5000'
PASSED = 0
DEGRADED = 0
VULNERABLE = 0
RESULTS = []


def log(status, name, detail=''):
    global PASSED, DEGRADED, VULNERABLE
    icon = {'SURVIVED': '✓', 'DEGRADED': '⚠', 'VULNERABLE': '✗'}[status]
    color_map = {'SURVIVED': PASSED, 'DEGRADED': DEGRADED, 'VULNERABLE': VULNERABLE}
    if status == 'SURVIVED':
        PASSED += 1
    elif status == 'DEGRADED':
        DEGRADED += 1
    else:
        VULNERABLE += 1
    RESULTS.append({'status': status, 'name': name, 'detail': detail})
    trunc = detail[:120] + '...' if len(detail) > 120 else detail
    print(f'  {icon} {status:11s}  {name} — {trunc}')


def safe_get(url, timeout=30):
    try:
        return requests.get(f'{BASE}{url}', timeout=timeout)
    except Exception as e:
        return e


def safe_post(url, data=None, timeout=30):
    try:
        return requests.post(f'{BASE}{url}', json=data, timeout=timeout)
    except Exception as e:
        return e


def health_check():
    for i in range(5):
        try:
            r = requests.get(f'{BASE}/api/health', timeout=10)
            if r.status_code == 200:
                return True
        except Exception:
            pass
        time.sleep(2)
    return False


# ═══════════════════════════════════════════
# WAVE 1A: HTTP FLOOD — Can we starve the thread pool?
# ═══════════════════════════════════════════

def test_concurrent_get_flood():
    """Fire 200 simultaneous GET requests at /api/health.
    128-thread Waitress should absorb this without dropping."""
    errors = 0
    success = 0
    t0 = time.time()

    def hit(_):
        try:
            r = requests.get(f'{BASE}/api/health', timeout=15)
            return r.status_code == 200
        except Exception:
            return False

    with ThreadPoolExecutor(max_workers=50) as pool:
        futures = [pool.submit(hit, i) for i in range(200)]
        for f in as_completed(futures):
            if f.result():
                success += 1
            else:
                errors += 1

    elapsed = time.time() - t0
    if errors == 0:
        log('SURVIVED', 'GET flood (200 concurrent)', f'{success}/200 OK, {elapsed:.1f}s')
    elif errors < 10:
        log('DEGRADED', 'GET flood (200 concurrent)', f'{success}/200 OK, {errors} dropped, {elapsed:.1f}s')
    else:
        log('VULNERABLE', 'GET flood (200 concurrent)', f'{success}/200 OK, {errors} DROPPED, {elapsed:.1f}s')


def test_mixed_endpoint_flood():
    """Hit 10 different endpoints simultaneously — simulates aggressive UI."""
    endpoints = [
        '/api/health', '/api/system/status', '/api/security/processes',
        '/api/security/network', '/api/security/ports', '/api/security/connections',
        '/api/hardware/gpu', '/api/hardware/memory', '/api/hardware/battery',
        '/api/threats/status'
    ]
    errors = 0
    t0 = time.time()

    def hit(url):
        try:
            r = requests.get(f'{BASE}{url}', timeout=20)
            return r.status_code == 200
        except Exception:
            return False

    with ThreadPoolExecutor(max_workers=30) as pool:
        # Each endpoint hit 10 times = 100 total
        futures = [pool.submit(hit, endpoints[i % len(endpoints)]) for i in range(100)]
        for f in as_completed(futures):
            if not f.result():
                errors += 1

    elapsed = time.time() - t0
    if errors == 0:
        log('SURVIVED', 'Mixed endpoint flood (100 reqs)', f'0 errors, {elapsed:.1f}s')
    elif errors < 5:
        log('DEGRADED', 'Mixed endpoint flood (100 reqs)', f'{errors} errors, {elapsed:.1f}s')
    else:
        log('VULNERABLE', 'Mixed endpoint flood (100 reqs)', f'{errors} ERRORS, {elapsed:.1f}s')


# ═══════════════════════════════════════════
# WAVE 1B: SCAN RACE CONDITIONS
# ═══════════════════════════════════════════

def test_concurrent_scan_race():
    """Fire 20 simultaneous /scan requests.
    Mutex should ensure exactly 1 scan runs, others get cached."""
    results = []
    t0 = time.time()

    def fire_scan(_):
        try:
            r = requests.get(f'{BASE}/api/threats/scan', timeout=120)
            return r.status_code, r.json().get('score', -1)
        except Exception as e:
            return -1, str(e)

    with ThreadPoolExecutor(max_workers=20) as pool:
        futures = [pool.submit(fire_scan, i) for i in range(20)]
        for f in as_completed(futures):
            results.append(f.result())

    elapsed = time.time() - t0
    ok_count = sum(1 for code, _ in results if code == 200)
    scores = [s for _, s in results if isinstance(s, int) and s >= 0]
    unique_scores = set(scores)

    if ok_count == 20 and len(unique_scores) <= 2:
        log('SURVIVED', 'Scan race (20 concurrent)', f'{ok_count}/20 OK, scores={unique_scores}, {elapsed:.1f}s')
    elif ok_count >= 15:
        log('DEGRADED', 'Scan race (20 concurrent)', f'{ok_count}/20 OK, scores={unique_scores}, {elapsed:.1f}s')
    else:
        log('VULNERABLE', 'Scan race (20 concurrent)', f'{ok_count}/20 OK, {elapsed:.1f}s')


def test_scan_then_flood_score():
    """Start a scan, then immediately flood /score 50 times.
    Score endpoint should never block on the scan worker."""
    # Trigger scan
    threading.Thread(target=lambda: safe_get('/api/threats/scan', timeout=120), daemon=True).start()
    time.sleep(0.5)  # Let scan start

    errors = 0
    t0 = time.time()

    def hit_score(_):
        try:
            r = requests.get(f'{BASE}/api/threats/score', timeout=10)
            return r.status_code == 200
        except Exception:
            return False

    with ThreadPoolExecutor(max_workers=20) as pool:
        futures = [pool.submit(hit_score, i) for i in range(50)]
        for f in as_completed(futures):
            if not f.result():
                errors += 1

    elapsed = time.time() - t0
    if errors == 0 and elapsed < 15:
        log('SURVIVED', 'Score flood during scan (50 reqs)', f'0 errors, {elapsed:.1f}s')
    elif errors == 0:
        log('DEGRADED', 'Score flood during scan (50 reqs)', f'0 errors but slow: {elapsed:.1f}s')
    else:
        log('VULNERABLE', 'Score flood during scan (50 reqs)', f'{errors} ERRORS, {elapsed:.1f}s')


# ═══════════════════════════════════════════
# WAVE 1C: MALFORMED INPUTS
# ═══════════════════════════════════════════

def test_huge_json_payload():
    """Send a 5MB JSON blob to /api/ai/analyze. Should reject or handle gracefully."""
    huge = {'findings': [{'id': f'EVIL-{i}', 'title': 'x' * 1000,
                          'severity': 'critical', 'category': 'test',
                          'detail': 'y' * 5000, 'recommendation': 'z' * 1000}
                         for i in range(500)]}
    try:
        r = requests.post(f'{BASE}/api/ai/analyze', json=huge, timeout=60)
        if r.status_code in (200, 400, 413):
            log('SURVIVED', 'Huge JSON payload (5MB)', f'Status={r.status_code}, handled gracefully')
        else:
            log('DEGRADED', 'Huge JSON payload (5MB)', f'Status={r.status_code}')
    except requests.exceptions.ReadTimeout:
        log('DEGRADED', 'Huge JSON payload (5MB)', 'Timed out at 60s — Ollama choked on large input')
    except Exception as e:
        log('VULNERABLE', 'Huge JSON payload (5MB)', str(e))


def test_malformed_json_body():
    """Send garbage bytes as JSON. Should get 400/415, not 500."""
    try:
        r = requests.post(f'{BASE}/api/ai/ask', data=b'NOT JSON {{{',
                          headers={'Content-Type': 'application/json'}, timeout=10)
        if r.status_code == 400:
            log('SURVIVED', 'Malformed JSON body', f'Got 400 as expected')
        elif r.status_code < 500:
            log('SURVIVED', 'Malformed JSON body', f'Got {r.status_code} — non-crash')
        else:
            log('VULNERABLE', 'Malformed JSON body', f'Got {r.status_code} — server error!')
    except Exception as e:
        log('VULNERABLE', 'Malformed JSON body', str(e))


def test_missing_required_fields():
    """Send empty body to /api/ai/ask (expects 'question' field)."""
    try:
        r = requests.post(f'{BASE}/api/ai/ask', json={}, timeout=10)
        if r.status_code == 400:
            log('SURVIVED', 'Missing required fields (/ask)', f'Got 400 as expected')
        elif r.status_code == 200:
            # Still survived — just returned empty/default answer
            log('SURVIVED', 'Missing required fields (/ask)', f'Got 200 — graceful default')
        else:
            log('DEGRADED', 'Missing required fields (/ask)', f'Got {r.status_code}')
    except Exception as e:
        log('VULNERABLE', 'Missing required fields (/ask)', str(e))


def test_wrong_content_type():
    """Send form-encoded data to a JSON endpoint."""
    try:
        r = requests.post(f'{BASE}/api/ai/ask',
                          data='question=test',
                          headers={'Content-Type': 'application/x-www-form-urlencoded'},
                          timeout=10)
        if r.status_code < 500:
            log('SURVIVED', 'Wrong Content-Type (form to JSON)', f'Status={r.status_code}')
        else:
            log('VULNERABLE', 'Wrong Content-Type (form to JSON)', f'Status={r.status_code}')
    except Exception as e:
        log('VULNERABLE', 'Wrong Content-Type (form to JSON)', str(e))


def test_extremely_long_url():
    """Send a 10KB query string. Waitress should reject or handle."""
    try:
        long_param = 'x' * 10000
        r = requests.get(f'{BASE}/api/health?q={long_param}', timeout=10)
        if r.status_code in (200, 400, 414):
            log('SURVIVED', 'Extremely long URL (10KB)', f'Status={r.status_code}')
        else:
            log('DEGRADED', 'Extremely long URL (10KB)', f'Status={r.status_code}')
    except Exception as e:
        log('VULNERABLE', 'Extremely long URL (10KB)', str(e))


# ═══════════════════════════════════════════
# WAVE 1D: DEFENSE STATE RAPID TOGGLE
# ═══════════════════════════════════════════

def test_defense_rapid_toggle():
    """Toggle each defense module 20 times in rapid succession.
    State should be consistent at the end."""
    modules = [
        ('shield', '/api/defense/shield/engage', '/api/defense/shield/disengage'),
        ('trap', '/api/defense/trap/activate', '/api/defense/trap/deactivate'),
        ('mirror', '/api/defense/mirror/activate', '/api/defense/mirror/deactivate'),
        ('sentinel', '/api/defense/sentinel/activate', '/api/defense/sentinel/deactivate'),
    ]
    total_errors = 0
    for name, engage, disengage in modules:
        for i in range(20):
            try:
                requests.post(f'{BASE}{engage}', json={}, timeout=5)
                requests.post(f'{BASE}{disengage}', json={}, timeout=5)
            except Exception:
                total_errors += 1

    # Check final state — all should be inactive
    try:
        r = requests.get(f'{BASE}/api/defense/status', timeout=10)
        status = r.json()
        all_off = all(not status[k].get('active', False)
                      for k in ['aegis_shield', 'shadow_trap', 'mirror_gate', 'sentinel']
                      if k in status)
        if all_off and total_errors == 0:
            log('SURVIVED', 'Defense rapid toggle (80 cycles)', 'All modules inactive, 0 errors')
        elif all_off:
            log('DEGRADED', 'Defense rapid toggle (80 cycles)', f'{total_errors} errors but state consistent')
        else:
            log('VULNERABLE', 'Defense rapid toggle (80 cycles)', 'STATE INCONSISTENT after rapid toggle')
    except Exception as e:
        log('VULNERABLE', 'Defense rapid toggle (80 cycles)', str(e))


def test_defense_concurrent_toggle():
    """Toggle all 4 modules simultaneously from 10 threads.
    Tests for state corruption under concurrent access."""
    errors = 0

    def toggle(name, on, off):
        for _ in range(5):
            try:
                requests.post(f'{BASE}{on}', json={}, timeout=5)
                requests.post(f'{BASE}{off}', json={}, timeout=5)
            except Exception:
                return False
        return True

    modules = [
        ('shield', '/api/defense/shield/engage', '/api/defense/shield/disengage'),
        ('trap', '/api/defense/trap/activate', '/api/defense/trap/deactivate'),
        ('mirror', '/api/defense/mirror/activate', '/api/defense/mirror/deactivate'),
        ('sentinel', '/api/defense/sentinel/activate', '/api/defense/sentinel/deactivate'),
    ]

    with ThreadPoolExecutor(max_workers=10) as pool:
        futures = []
        for _ in range(3):  # 3 rounds of all 4 modules
            for name, on, off in modules:
                futures.append(pool.submit(toggle, name, on, off))
        for f in as_completed(futures):
            if not f.result():
                errors += 1

    if errors == 0:
        log('SURVIVED', 'Defense concurrent toggle (12 threads)', '0 errors')
    else:
        log('DEGRADED', 'Defense concurrent toggle (12 threads)', f'{errors} errors')


# ═══════════════════════════════════════════
# WAVE 1E: POST-ATTACK HEALTH VERIFICATION
# ═══════════════════════════════════════════

def test_post_attack_health():
    """After all the abuse — is the backend still responsive?"""
    t0 = time.time()
    try:
        r = requests.get(f'{BASE}/api/health', timeout=10)
        elapsed = time.time() - t0
        if r.status_code == 200 and elapsed < 5:
            log('SURVIVED', 'Post-attack health check', f'Healthy in {elapsed:.2f}s')
        elif r.status_code == 200:
            log('DEGRADED', 'Post-attack health check', f'Healthy but slow: {elapsed:.2f}s')
        else:
            log('VULNERABLE', 'Post-attack health check', f'Status={r.status_code}')
    except Exception as e:
        log('VULNERABLE', 'Post-attack health check', str(e))


def test_post_attack_scan():
    """Can we still run a clean scan after the destruction campaign?"""
    try:
        r = requests.get(f'{BASE}/api/threats/scan', timeout=120)
        if r.status_code == 200:
            data = r.json()
            score = data.get('score', -1)
            findings = len(data.get('findings', []))
            if score >= 0:
                log('SURVIVED', 'Post-attack scan integrity', f'Score={score}, Findings={findings}')
            else:
                log('VULNERABLE', 'Post-attack scan integrity', 'Invalid score')
        else:
            log('VULNERABLE', 'Post-attack scan integrity', f'Status={r.status_code}')
    except Exception as e:
        log('VULNERABLE', 'Post-attack scan integrity', str(e))


def test_post_attack_thread_leak():
    """Check if the backend process has leaked threads during the campaign."""
    try:
        import psutil
        # Find the Flask/Waitress python process on port 5000
        for proc in psutil.process_iter(['pid', 'name', 'connections']):
            try:
                for conn in proc.connections(kind='inet'):
                    if conn.laddr.port == 5000 and conn.status == 'LISTEN':
                        thread_count = proc.num_threads()
                        if thread_count < 200:
                            log('SURVIVED', 'Post-attack thread leak check',
                                f'Backend threads: {thread_count} (< 200 cap)')
                        elif thread_count < 300:
                            log('DEGRADED', 'Post-attack thread leak check',
                                f'Backend threads: {thread_count} — ELEVATED')
                        else:
                            log('VULNERABLE', 'Post-attack thread leak check',
                                f'Backend threads: {thread_count} — LEAKING!')
                        return
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        log('DEGRADED', 'Post-attack thread leak check', 'Could not find backend process')
    except ImportError:
        log('DEGRADED', 'Post-attack thread leak check', 'psutil not available')


# ═══════════════════════════════════════════
# EXECUTION
# ═══════════════════════════════════════════

if __name__ == '__main__':
    print('╔══════════════════════════════════════════════╗')
    print('║  AEGIS PROTECT — DESTRUCTION CAMPAIGN: W1    ║')
    print('║  Surface: HTTP/API + Concurrency + State     ║')
    print('╚══════════════════════════════════════════════╝')
    print()
    print(f'Target: {BASE}')
    print(f'Time:   {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}')

    if not health_check():
        print('FATAL: Backend not responding. Start the app first.')
        sys.exit(1)
    print(f'Backend: HEALTHY ✓')
    print()

    # ═══ A. HTTP FLOOD ═══
    print('═══ A. HTTP FLOOD ═══')
    test_concurrent_get_flood()
    test_mixed_endpoint_flood()
    print()

    # ═══ B. SCAN RACE CONDITIONS ═══
    print('═══ B. SCAN RACE CONDITIONS ═══')
    test_concurrent_scan_race()
    test_scan_then_flood_score()
    print()

    # ═══ C. MALFORMED INPUTS ═══
    print('═══ C. MALFORMED INPUTS ═══')
    test_huge_json_payload()
    test_malformed_json_body()
    test_missing_required_fields()
    test_wrong_content_type()
    test_extremely_long_url()
    print()

    # ═══ D. DEFENSE STATE ABUSE ═══
    print('═══ D. DEFENSE STATE ABUSE ═══')
    test_defense_rapid_toggle()
    test_defense_concurrent_toggle()
    print()

    # ═══ E. POST-ATTACK VERIFICATION ═══
    print('═══ E. POST-ATTACK VERIFICATION ═══')
    test_post_attack_health()
    test_post_attack_scan()
    test_post_attack_thread_leak()
    print()

    # ═══ FINAL REPORT ═══
    total = PASSED + DEGRADED + VULNERABLE
    print('══════════════════════════════════════════════════')
    print(f'  RESULTS:  {PASSED} SURVIVED  |  {DEGRADED} DEGRADED  |  {VULNERABLE} VULNERABLE  ({total} total)')
    print('══════════════════════════════════════════════════')
    if VULNERABLE == 0:
        print()
        print('  ✓ WAVE 1 CLEARED — NO VULNERABILITIES FOUND')
    else:
        print()
        print(f'  ✗ {VULNERABLE} VULNERABILITIES FOUND — REMEDIATION REQUIRED')
        for r in RESULTS:
            if r['status'] == 'VULNERABLE':
                print(f'    → {r["name"]}: {r["detail"][:100]}')
    print()

    sys.exit(0 if VULNERABLE == 0 else 1)
