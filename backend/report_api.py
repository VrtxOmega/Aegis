"""
Aegis Report API — PDF Audit Report Generation
================================================
Generates branded VERITAS PDF reports from scan data, AI narratives,
and remediation history using the veritas_pdf generator.
"""
import os
import socket
import platform
from datetime import datetime
from flask import Blueprint, jsonify, request

from veritas_pdf import convert_text

report_bp = Blueprint('report', __name__)

REPORTS_DIR = os.path.join(os.path.dirname(__file__), '..', 'reports')


def _severity_sort_key(severity):
    """Sort priority: critical > high > medium > low > info."""
    order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3, 'info': 4}
    return order.get(severity.lower(), 5)


def _build_report_markdown(data):
    """Build a markdown document from scan report data."""
    findings = data.get('findings', [])
    score = data.get('score', 'N/A')
    narrative = data.get('ai_narrative', '')
    resolutions = data.get('resolutions', [])
    scan_duration = data.get('scan_duration_ms', 0)
    project_name = data.get('project_name', '')

    # Sort findings by severity
    findings_sorted = sorted(findings, key=lambda f: _severity_sort_key(f.get('severity', 'info')))

    # Count by severity
    sev_counts = {}
    for f in findings_sorted:
        s = f.get('severity', 'info').upper()
        sev_counts[s] = sev_counts.get(s, 0) + 1

    timestamp = datetime.now().strftime('%B %d, %Y at %H:%M')
    hostname = socket.gethostname()
    os_info = f"{platform.system()} {platform.release()}"

    lines = []

    # Cover
    title = "Threat Assessment Report"
    if project_name:
        title = f"Threat Assessment Report: {project_name}"
    lines.append(f"# {title}")
    lines.append(f"### Security Scan Results — {timestamp}")
    lines.append("")

    # Executive summary section
    lines.append("## Executive Summary")
    lines.append("")
    lines.append(f"**Security Score: {score}/100**")
    lines.append("")

    if sev_counts:
        sev_parts = [f"{count} {sev}" for sev, count in sev_counts.items()]
        lines.append(f"Total findings: {len(findings_sorted)} ({', '.join(sev_parts)})")
    else:
        lines.append("No security issues detected. System is clean.")
    lines.append("")

    if scan_duration:
        lines.append(f"Scan completed in {scan_duration / 1000:.1f} seconds")
        lines.append("")

    # AI Narrative
    if narrative:
        lines.append("## AI Threat Analysis")
        lines.append("")
        lines.append(narrative)
        lines.append("")

    # Findings table
    if findings_sorted:
        lines.append("## Detailed Findings")
        lines.append("")
        lines.append("| Severity | Category | Title | File | Line |")
        lines.append("|----------|----------|-------|------|------|")
        for f in findings_sorted:
            sev = f.get('severity', 'info').upper()
            cat = f.get('category', 'Unknown')
            title = f.get('title', 'Untitled')
            file = f.get('file', '-')
            line = f.get('line', '-')
            lines.append(f"| {sev} | {cat} | {title} | {file} | {line} |")
        lines.append("")

        # Detailed descriptions
        lines.append("### Finding Details")
        lines.append("")
        for i, f in enumerate(findings_sorted, 1):
            sev = f.get('severity', 'info').upper()
            lines.append(f"**{i}. [{sev}] {f.get('title', 'Untitled')}**")
            lines.append("")
            if f.get('detail'):
                lines.append(f"{f['detail']}")
                lines.append("")
            if f.get('recommendation'):
                lines.append(f"*Recommendation: {f['recommendation']}*")
                lines.append("")

    # Remediation history
    if resolutions:
        lines.append("## Remediation History")
        lines.append("")
        lines.append("| Status | Category | Title | Resolved At |")
        lines.append("|--------|----------|-------|-------------|")
        for r in resolutions:
            status = r.get('status', 'UNKNOWN')
            cat = r.get('category', '-')
            title = r.get('title', '-')
            resolved = r.get('resolved_at', '-')
            lines.append(f"| {status} | {cat} | {title} | {resolved} |")
        lines.append("")

    # System profile
    lines.append("## System Profile")
    lines.append("")
    lines.append(f"- **Hostname**: {hostname}")
    lines.append(f"- **Operating System**: {os_info}")
    lines.append(f"- **Report Generated**: {timestamp}")
    lines.append(f"- **Scanner Version**: Aegis Protect v2.4.0")
    lines.append("")

    # Closing
    lines.append("---")
    lines.append("")
    lines.append("> Your system. Your shield. Your rules.")
    lines.append("")
    lines.append("RJ Lopez | RJ@AegisAudits.com | aegisaudits.com")

    return "\n".join(lines)


@report_bp.route('/api/report/generate', methods=['POST'])
def generate_report():
    """Generate a branded PDF report from scan data."""
    try:
        data = request.get_json() or {}

        # Build markdown from scan data
        md_text = _build_report_markdown(data)

        # Generate output path
        os.makedirs(REPORTS_DIR, exist_ok=True)
        stamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        project = data.get('project_name', 'scan')
        # Sanitize project name for filename
        safe_name = "".join(c if c.isalnum() or c in '-_' else '_' for c in project)
        filename = f"Aegis_Report_{safe_name}_{stamp}.pdf"
        output_path = os.path.join(REPORTS_DIR, filename)
        output_path = os.path.abspath(output_path)

        # Generate PDF
        result_path = convert_text(
            md_text,
            output_path,
            title=None,  # Use title from markdown
            auto_open=False
        )

        if result_path and os.path.isfile(result_path):
            return jsonify({
                'status': 'success',
                'path': result_path,
                'filename': filename,
                'size_bytes': os.path.getsize(result_path),
            })
        else:
            return jsonify({'status': 'error', 'error': 'PDF generation failed'}), 500

    except Exception as e:
        return jsonify({'status': 'error', 'error': str(e)}), 500


@report_bp.route('/api/report/list', methods=['GET'])
def list_reports():
    """List previously generated reports."""
    try:
        os.makedirs(REPORTS_DIR, exist_ok=True)
        reports = []
        for f in sorted(os.listdir(REPORTS_DIR), reverse=True):
            if f.endswith('.pdf'):
                path = os.path.join(REPORTS_DIR, f)
                reports.append({
                    'filename': f,
                    'path': os.path.abspath(path),
                    'size_bytes': os.path.getsize(path),
                    'created_at': datetime.fromtimestamp(
                        os.path.getctime(path)
                    ).isoformat(),
                })
        return jsonify({'reports': reports})
    except Exception as e:
        return jsonify({'reports': [], 'error': str(e)})
