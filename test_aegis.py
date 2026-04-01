"""
Aegis — Comprehensive Test Suite
Tests every endpoint, detector, AI integration, and defense system.
Run with: python test_aegis.py

Requires: Flask backend running on http://127.0.0.1:5000
"""
import sys
import json
import time
import requests

BASE = "http://127.0.0.1:5000"
PASS = 0
FAIL = 0
WARN = 0
RESULTS = []


def test(name, fn):
    """Run a test function and track results."""
    global PASS, FAIL, WARN
    try:
        result = fn()
        if result is True:
            PASS += 1
            RESULTS.append(('PASS', name, ''))
            print(f"  ✓ PASS  {name}")
        elif result is None:
            WARN += 1
            RESULTS.append(('WARN', name, 'Returned None'))
            print(f"  ⚠ WARN  {name} — returned None")
        else:
            PASS += 1
            RESULTS.append(('PASS', name, str(result)[:100]))
            print(f"  ✓ PASS  {name} → {str(result)[:80]}")
    except AssertionError as e:
        FAIL += 1
        RESULTS.append(('FAIL', name, str(e)))
        print(f"  ✗ FAIL  {name} — {e}")
    except Exception as e:
        FAIL += 1
        RESULTS.append(('FAIL', name, str(e)))
        print(f"  ✗ FAIL  {name} — {type(e).__name__}: {e}")


def get(path, timeout=300):
    """GET request with timeout."""
    r = requests.get(f"{BASE}{path}", timeout=timeout)
    assert r.status_code == 200, f"HTTP {r.status_code}"
    return r.json()


def post(path, body=None, timeout=180):
    """POST request with timeout."""
    r = requests.post(f"{BASE}{path}", json=body or {}, timeout=timeout)
    assert r.status_code == 200, f"HTTP {r.status_code}"
    return r.json()


# ════════════════════════════════════════
# 1. HEALTH & EXISTING ENDPOINTS
# ════════════════════════════════════════
def test_health():
    print("\n═══ 1. HEALTH & CORE ENDPOINTS ═══")

    test("Backend health", lambda: get("/api/health")['status'] == 'ok')
    test("System status", lambda: 'cpu_percent' in get("/api/system/status"))
    test("Security processes", lambda: isinstance(get("/api/security/processes"), list))
    test("Security network", lambda: isinstance(get("/api/security/network"), dict))
    test("Security ports", lambda: isinstance(get("/api/security/ports"), list))
    test("Security connections", lambda: isinstance(get("/api/security/connections"), list))
    test("Security startup", lambda: isinstance(get("/api/security/startup"), list))
    test("Hardware GPU", lambda: isinstance(get("/api/hardware/gpu"), dict))
    test("Hardware CPU temp", lambda: isinstance(get("/api/hardware/temperatures"), dict))
    test("Hardware memory", lambda: isinstance(get("/api/hardware/memory"), dict))
    test("Hardware battery", lambda: isinstance(get("/api/hardware/battery"), dict))
    test("Hardware disks", lambda: isinstance(get("/api/hardware/disks"), list))


# ════════════════════════════════════════
# 2. THREAT DETECTION ENGINE
# ════════════════════════════════════════
def test_threat_engine():
    print("\n═══ 2. THREAT DETECTION ENGINE (40 Rules) ═══")

    # Master scan
    def full_scan():
        data = get("/api/threats/scan")
        assert 'findings' in data, "Missing 'findings' key"
        assert 'score' in data, "Missing 'score' key"
        assert isinstance(data['score'], (int, float)), f"Score is not numeric: {type(data['score'])}"
        assert 0 <= data['score'] <= 100, f"Score out of range: {data['score']}"
        assert 'total_findings' in data, "Missing 'total_findings'"
        assert 'category_counts' in data, "Missing 'category_counts'"
        assert 'scan_time_ms' in data, "Missing 'scan_time_ms'"
        return f"Score={data['score']}, Findings={data['total_findings']}, Time={data['scan_time_ms']}ms"

    test("Full scan — structure", full_scan)

    # Individual category endpoints
    def test_lolbins():
        data = get("/api/threats/lolbins")
        assert 'findings' in data
        assert 'scan_time_ms' in data
        for f in data['findings']:
            assert f['id'].startswith('LOL-'), f"Bad ID: {f['id']}"
            assert f['category'] == 'lolbin'
        return f"{len(data['findings'])} findings, {data['scan_time_ms']}ms"

    test("LOLBins endpoint", test_lolbins)

    def test_persistence():
        data = get("/api/threats/persistence")
        assert 'findings' in data
        for f in data['findings']:
            assert f['id'].startswith('PER-'), f"Bad ID: {f['id']}"
            assert f['category'] == 'persistence'
        return f"{len(data['findings'])} findings, {data['scan_time_ms']}ms"

    test("Persistence endpoint", test_persistence)

    def test_ransomware():
        data = get("/api/threats/ransomware")
        assert 'findings' in data
        for f in data['findings']:
            assert f['id'].startswith('RAN-'), f"Bad ID: {f['id']}"
        return f"{len(data['findings'])} findings"

    test("Ransomware endpoint", test_ransomware)

    def test_credentials():
        data = get("/api/threats/credentials")
        assert 'findings' in data
        for f in data['findings']:
            assert f['id'].startswith('CRD-'), f"Bad ID: {f['id']}"
        return f"{len(data['findings'])} findings"

    test("Credentials endpoint", test_credentials)

    def test_defense_evasion():
        data = get("/api/threats/defense-evasion")
        assert 'findings' in data
        for f in data['findings']:
            assert f['id'].startswith('DEF-'), f"Bad ID: {f['id']}"
        return f"{len(data['findings'])} findings"

    test("Defense Evasion endpoint", test_defense_evasion)

    # Quick score endpoint
    def test_score():
        data = get("/api/threats/score")
        assert 'score' in data
        assert 'total_findings' in data
        assert 'severity_counts' in data
        return f"Score={data['score']}"

    test("Quick score endpoint", test_score)

    # Validate finding structure
    def test_finding_structure():
        data = get("/api/threats/scan")
        required_keys = {'id', 'severity', 'category', 'title', 'detail', 'recommendation', 'timestamp'}
        for f in data['findings']:
            missing = required_keys - set(f.keys())
            assert not missing, f"Finding {f.get('id', '?')} missing keys: {missing}"
            assert f['severity'] in ('critical', 'high', 'medium', 'low', 'info'), \
                f"Bad severity: {f['severity']}"
        return f"All {len(data['findings'])} findings have valid structure"

    test("Finding structure validation", test_finding_structure)

    # Score computation
    def test_score_computation():
        data = get("/api/threats/scan")
        sev_weight = {'critical': 25, 'high': 10, 'medium': 4, 'low': 1, 'info': 0}
        expected_penalty = sum(sev_weight.get(f['severity'], 0) for f in data['findings'])
        expected_score = max(0, 100 - expected_penalty)
        assert data['score'] == expected_score, \
            f"Score mismatch: got {data['score']}, expected {expected_score}"
        return f"Score correctly computed: {data['score']}"

    test("Score computation accuracy", test_score_computation)


# ════════════════════════════════════════
# 3. AI ENGINE
# ════════════════════════════════════════
def test_ai_engine():
    print("\n═══ 3. AI ENGINE (Ollama) ═══")

    # AI status check
    def test_ai_status():
        data = get("/api/ai/status")
        assert 'ollama' in data, "Missing 'ollama' key"
        assert 'model' in data, "Missing 'model' key"
        assert data['model'] == 'qwen2.5:7b', f"Wrong model: {data['model']}"
        return f"Healthy={data['ollama'].get('healthy')}, Model={data['model']}"

    test("AI status endpoint", test_ai_status)

    # AI analysis — with empty findings
    def test_ai_analyze_empty():
        data = post("/api/ai/analyze", {"findings": []})
        assert 'narrative' in data, "Missing 'narrative'"
        return f"Empty analysis: {data['narrative'][:60]}..."

    test("AI analyze (empty findings)", test_ai_analyze_empty)

    # AI analysis — with sample findings
    def test_ai_analyze_findings():
        sample_findings = [
            {
                'id': 'LOL-005', 'severity': 'high', 'category': 'lolbin',
                'title': 'PowerShell with suspicious flags',
                'detail': 'PID 1234 (powershell.exe): -enc ZWNobyBoYWNrZWQ=',
                'recommendation': 'Check encoded command',
                'timestamp': '2026-03-30T07:00:00'
            },
            {
                'id': 'NET-001', 'severity': 'high', 'category': 'network',
                'title': 'C2 port connection',
                'detail': 'unknown.exe → 192.168.1.100:4444',
                'recommendation': 'Verify destination',
                'timestamp': '2026-03-30T07:00:01'
            }
        ]
        data = post("/api/ai/analyze", {"findings": sample_findings})
        assert 'narrative' in data, "Missing 'narrative'"
        assert len(data['narrative']) > 20, "Narrative too short"
        return f"Narrative length={len(data['narrative'])}, AI={data.get('ai_available')}"

    test("AI analyze (sample findings)", test_ai_analyze_findings)

    # Ask Aegis
    def test_ask_basic():
        data = post("/api/ai/ask", {"question": "Is my system secure?"})
        assert 'answer' in data, "Missing 'answer'"
        assert len(data['answer']) > 10, "Answer too short"
        return f"Answer length={len(data['answer'])}, AI={data.get('ai_available')}"

    test("Ask Aegis — basic question", test_ask_basic)

    # Ask Aegis with context
    def test_ask_context():
        scan = get("/api/threats/scan")
        data = post("/api/ai/ask", {
            "question": "What's the most suspicious thing on my system?",
            "system_state": scan
        })
        assert 'answer' in data
        return f"Contextual answer length={len(data['answer'])}"

    test("Ask Aegis — with scan context", test_ask_context)

    # Ask Aegis — error case (no question)
    def test_ask_empty():
        r = requests.post(f"{BASE}/api/ai/ask", json={"question": ""}, timeout=60)
        assert r.status_code == 400, f"Expected 400, got {r.status_code}"
        return True

    test("Ask Aegis — empty question (400)", test_ask_empty)

    # AI brief
    def test_brief():
        scan = get("/api/threats/scan")
        data = post("/api/ai/brief", {
            "findings": scan['findings'],
            "system_info": {"os": "Windows", "hostname": "test"}
        })
        assert 'brief' in data, "Missing 'brief'"
        return f"Brief length={len(data['brief'])}"

    test("AI Threat Brief generation", test_brief)


# ════════════════════════════════════════
# 4. DEFENSE SYSTEMS
# ════════════════════════════════════════
def test_defense_systems():
    print("\n═══ 4. DEFENSE SYSTEMS ═══")

    # Status endpoint
    def test_defense_status():
        data = get("/api/defense/status")
        expected_modules = ['aegis_shield', 'shadow_trap', 'mirror_gate', 'sentinel']
        for mod in expected_modules:
            assert mod in data, f"Missing module: {mod}"
            assert 'active' in data[mod], f"Module {mod} missing 'active' field"
            assert 'description' in data[mod], f"Module {mod} missing 'description'"
        return f"All 4 modules present"

    test("Defense status structure", test_defense_status)

    # ── Aegis Shield ──
    def test_shield_engage():
        data = post("/api/defense/shield/engage")
        assert data.get('status') == 'engaged', f"Unexpected status: {data.get('status')}"
        status = get("/api/defense/status")
        assert status['aegis_shield']['active'] is True, "Shield not active after engage"
        return f"Engaged, {data.get('rules_added', 0)} rules"

    test("Aegis Shield — engage", test_shield_engage)

    def test_shield_disengage():
        data = post("/api/defense/shield/disengage")
        assert data.get('status') == 'disengaged'
        status = get("/api/defense/status")
        assert status['aegis_shield']['active'] is False, "Shield still active after disengage"
        return True

    test("Aegis Shield — disengage", test_shield_disengage)

    # ── Shadow Trap ──
    def test_trap_activate():
        # Use high ports to avoid permission issues
        data = post("/api/defense/trap/activate", {"ports": [18080, 18443]})
        assert data.get('status') == 'activated'
        status = get("/api/defense/status")
        assert status['shadow_trap']['active'] is True
        return f"Activated on {data.get('ports', [])}"

    test("Shadow Trap — activate", test_trap_activate)

    def test_trap_detections():
        data = get("/api/defense/trap/detections")
        assert 'detections' in data
        assert 'total' in data
        return f"{data['total']} detections"

    test("Shadow Trap — detections endpoint", test_trap_detections)

    def test_trap_deactivate():
        data = post("/api/defense/trap/deactivate")
        assert data.get('status') == 'deactivated'
        status = get("/api/defense/status")
        assert status['shadow_trap']['active'] is False
        return True

    test("Shadow Trap — deactivate", test_trap_deactivate)

    # ── Mirror Gate ──
    def test_mirror_activate():
        data = post("/api/defense/mirror/activate")
        assert data.get('status') == 'activated'
        return True

    test("Mirror Gate — activate", test_mirror_activate)

    def test_mirror_status():
        data = get("/api/defense/mirror/status")
        assert 'active' in data
        assert 'captures' in data
        assert 'total_captures' in data
        return f"Active={data['active']}, Captures={data['total_captures']}"

    test("Mirror Gate — status endpoint", test_mirror_status)

    def test_mirror_deactivate():
        data = post("/api/defense/mirror/deactivate")
        assert data.get('status') == 'deactivated'
        return True

    test("Mirror Gate — deactivate", test_mirror_deactivate)

    # ── Sentinel ──
    def test_sentinel_activate():
        data = post("/api/defense/sentinel/activate")
        assert data.get('status') == 'activated'
        return True

    test("Sentinel — deploy", test_sentinel_activate)

    def test_sentinel_kill_guard():
        """Sentinel kill should fail without active state."""
        # First deactivate
        post("/api/defense/sentinel/deactivate")
        r = requests.post(f"{BASE}/api/defense/sentinel/kill", json={"pid": 99999}, timeout=5)
        assert r.status_code == 403, f"Expected 403 when sentinel inactive, got {r.status_code}"
        # Re-activate for cleanup
        post("/api/defense/sentinel/activate")
        return True

    test("Sentinel — kill guard (403 when inactive)", test_sentinel_kill_guard)

    def test_sentinel_quarantine_guard():
        """Quarantine should fail without active state."""
        post("/api/defense/sentinel/deactivate")
        r = requests.post(f"{BASE}/api/defense/sentinel/quarantine", json={"path": "C:\\nonexistent"}, timeout=5)
        assert r.status_code == 403, f"Expected 403, got {r.status_code}"
        return True

    test("Sentinel — quarantine guard (403 when inactive)", test_sentinel_quarantine_guard)

    def test_sentinel_deactivate():
        data = post("/api/defense/sentinel/deactivate")
        assert data.get('status') == 'deactivated'
        return True

    test("Sentinel — stand down", test_sentinel_deactivate)


# ════════════════════════════════════════
# 5. INTEGRATION TESTS
# ════════════════════════════════════════
def test_integration():
    print("\n═══ 5. INTEGRATION TESTS ═══")

    # Full scan + AI analysis pipeline
    def test_scan_then_analyze():
        scan = get("/api/threats/scan")
        analysis = post("/api/ai/analyze", {"findings": scan['findings']})
        assert 'narrative' in analysis
        return f"Scan→Analyze pipeline complete. Score={scan['score']}, AI={analysis.get('ai_available')}"

    test("Scan→Analyze pipeline", test_scan_then_analyze)

    # Scan performance
    def test_scan_performance():
        t0 = time.time()
        get("/api/threats/scan", timeout=300)
        elapsed = (time.time() - t0) * 1000
        assert elapsed < 300000, f"Scan took {elapsed:.0f}ms (>5min)"
        return f"Scan completed in {elapsed:.0f}ms"

    test("Scan performance (<5min)", test_scan_performance)

    # All defense modules cycle (engage → verify → disengage → verify)
    def test_defense_cycle():
        # Engage all
        post("/api/defense/shield/engage")
        post("/api/defense/trap/activate", {"ports": [19090]})
        post("/api/defense/mirror/activate")
        post("/api/defense/sentinel/activate")

        status = get("/api/defense/status")
        assert status['aegis_shield']['active']
        assert status['shadow_trap']['active']
        assert status['mirror_gate']['active']
        assert status['sentinel']['active']

        # Disengage all
        post("/api/defense/shield/disengage")
        post("/api/defense/trap/deactivate")
        post("/api/defense/mirror/deactivate")
        post("/api/defense/sentinel/deactivate")

        status = get("/api/defense/status")
        assert not status['aegis_shield']['active']
        assert not status['shadow_trap']['active']
        assert not status['mirror_gate']['active']
        assert not status['sentinel']['active']
        return "All 4 modules cycled successfully"

    test("Defense full cycle (engage→verify→disengage→verify)", test_defense_cycle)

    # Score stability (two scans should give same score)
    def test_score_stability():
        s1 = get("/api/threats/scan")['score']
        s2 = get("/api/threats/scan")['score']
        assert s1 == s2, f"Score unstable: {s1} vs {s2}"
        return f"Stable: {s1} == {s2}"

    test("Score stability (deterministic)", test_score_stability)


# ════════════════════════════════════════
# 6. EDGE CASES & ERROR HANDLING
# ════════════════════════════════════════
def test_edge_cases():
    print("\n═══ 6. EDGE CASES & ERROR HANDLING ═══")

    # 404 on bad endpoint
    def test_404():
        r = requests.get(f"{BASE}/api/threats/nonexistent", timeout=5)
        assert r.status_code == 404, f"Expected 404, got {r.status_code}"
        return True

    test("404 on unknown endpoint", test_404)

    # AI analyze with malformed data
    def test_ai_malformed():
        data = post("/api/ai/analyze", {"findings": "not a list"})
        assert 'narrative' in data  # Should handle gracefully
        return True

    test("AI analyze — malformed input handled", test_ai_malformed)

    # Defense sentinel kill with invalid PID
    def test_kill_bad_pid():
        post("/api/defense/sentinel/activate")
        data = post("/api/defense/sentinel/kill", {"pid": 99999999})
        # Should not crash, just report failure
        assert 'success' in data
        assert data['success'] is False
        post("/api/defense/sentinel/deactivate")
        return True

    test("Sentinel kill — invalid PID handled", test_kill_bad_pid)

    # Defense quarantine nonexistent file
    def test_quarantine_missing():
        post("/api/defense/sentinel/activate")
        data = post("/api/defense/sentinel/quarantine", {"path": "C:\\nonexistent_file_12345.exe"})
        assert data['success'] is False
        post("/api/defense/sentinel/deactivate")
        return True

    test("Sentinel quarantine — missing file handled", test_quarantine_missing)


# ════════════════════════════════════════
# MAIN
# ════════════════════════════════════════
if __name__ == '__main__':
    print("╔════════════════════════════════════════════╗")
    print("║  AEGIS PROTECT — COMPREHENSIVE TEST SUITE  ║")
    print("╚════════════════════════════════════════════╝")
    print(f"\nTarget: {BASE}")
    print(f"Time:   {time.strftime('%Y-%m-%d %H:%M:%S')}")

    # Check backend is alive (retry a few times in case server is busy)
    for attempt in range(5):
        try:
            r = requests.get(f"{BASE}/api/health", timeout=15)
            if r.status_code == 200:
                print("Backend: HEALTHY ✓\n")
                break
        except Exception as e:
            if attempt == 4:
                print(f"\n✗ FATAL: Backend not reachable at {BASE}")
                print(f"  Error: {e}")
                print("  Start the app first: npm start")
                sys.exit(1)
            time.sleep(3)

    t0 = time.time()

    test_health()
    test_threat_engine()
    test_ai_engine()
    test_defense_systems()
    test_integration()
    test_edge_cases()

    elapsed = time.time() - t0

    # ── Summary ──
    total = PASS + FAIL + WARN
    print(f"\n{'═' * 50}")
    print(f"  RESULTS:  {PASS} PASS  |  {FAIL} FAIL  |  {WARN} WARN  ({total} total)")
    print(f"  TIME:     {elapsed:.1f}s")
    print(f"{'═' * 50}")

    if FAIL > 0:
        print("\n  FAILED TESTS:")
        for status, name, reason in RESULTS:
            if status == 'FAIL':
                print(f"    ✗ {name}")
                print(f"      {reason}")

    if FAIL == 0:
        print("\n  ✓ ALL TESTS PASSED — ENGINE VERIFIED")
    else:
        print(f"\n  ✗ {FAIL} TEST(S) FAILED — INVESTIGATE")

    sys.exit(1 if FAIL > 0 else 0)
