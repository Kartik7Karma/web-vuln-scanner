# text_report_generator.py

import json
from datetime import datetime

def generate_text_report(results_data, output_file="report.txt"):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    report_lines = [f"📄 Web Vulnerability Scan Report - {timestamp}", "=" * 60]

    for entry in results_data:
        url = entry.get("url", "Unknown URL")
        report_lines.append(f"\n🔗 URL: {url}")

        # XSS
        for vuln in entry.get("xss", {}).get("vulnerabilities", []):
            report_lines.append(f"⚡ XSS:")
            report_lines.append(f"  - Payload: {vuln.get('payload', '')}")
            report_lines.append(f"  - Location: {vuln.get('location', '')}")

        # SQL Injection
        for vuln in entry.get("sql_injection", {}).get("vulnerabilities", []):
            report_lines.append(f"🧨 SQL Injection:")
            report_lines.append(f"  - Payload: {vuln.get('payload', '')}")
            report_lines.append(f"  - Location: {vuln.get('location', '')}")

        # Command Injection
        for vuln in entry.get("cmd_injection", {}).get("vulnerabilities", []):
            report_lines.append(f"💣 Command Injection:")
            report_lines.append(f"  - Payload: {vuln.get('data', '')}")
            report_lines.append(f"  - Location: {vuln.get('form_action', '')}")

        # Directory Traversal
        for vuln in entry.get("directory_traversal", {}).get("vulnerabilities", []):
            report_lines.append("🗂️ Directory Traversal:")
            report_lines.append(f"  - Payload: {vuln.get('payload', '')}")
            report_lines.append(f"  - URL: {vuln.get('url', '')}")

        # CSRF
        for issue in entry.get("csrf", {}).get("issues", []):
            report_lines.append("🔓 CSRF:")
            report_lines.append(f"  - Issue: {issue}")

        # Missing Security Headers
        for header in entry.get("headers", {}).get("missing", []):
            report_lines.append("🛡️ Missing Security Header:")
            report_lines.append(f"  - {header}")

    try:
        with open(output_file, 'w') as f:
            f.write("\n".join(report_lines))
        print(f"✅ Text report saved as {output_file}")
    except Exception as e:
        print(f"[!] Error writing text report: {e}")
