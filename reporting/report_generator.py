import json
import sys
from datetime import datetime

def generate_text_report(json_file, output_file=None):
    # Load scan result from JSON file
    try:
        with open(json_file, "r") as f:
            results = json.load(f)
    except Exception as e:
        print(f"[!] Error reading {json_file}: {e}")
        return

    now = datetime.now().strftime("%Y-%m-%d %I:%M %p")

    # Set default output file if not given
    if not output_file:
        output_file = f"scan_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"

    # Initialize counters for summary
    url_count = 0
    xss_total = 0
    sqli_total = 0
    cmd_total = 0
    csrf_total = 0
    misconfig_total = 0

    report_lines = []
    detailed_lines = []

    # Header
    report_lines.append("🧪 Web Vulnerability Scan Report")
    report_lines.append(f"📅 Generated: {now}")
    report_lines.append("=" * 60)

    # Loop through each scanned result
    for entry in results:
        url = entry.get("url", "Unknown URL")
        url_count += 1

        detailed_lines.append(f"\n🔗 URL: {url}")
        detailed_lines.append("=" * 60)

        # Reflected XSS
        xss_data = entry.get("xss", {}).get("vulnerabilities", [])
        if xss_data:
            xss_total += len(xss_data)
            detailed_lines.append("⚡ XSS Vulnerabilities:")
            for vuln in xss_data:
                payload = vuln.get("payload", "N/A")
                location = vuln.get("location", "unknown")
                detailed_lines.append(f" - Reflected XSS at: {location} | Payload: {payload}")

        # SQL Injection
        sqli_data = entry.get("sql_injection", {}).get("vulnerabilities", [])
        if sqli_data:
            sqli_total += len(sqli_data)
            detailed_lines.append("🧬 SQL Injection:")
            for vuln in sqli_data:
                payload = vuln.get("payload", "N/A")
                location = vuln.get("location", "unknown")
                detailed_lines.append(f" - SQLi at: {location} | Payload: {payload}")

        # Command Injection
        cmd_data = entry.get("cmd_injection", {}).get("vulnerabilities", [])
        if cmd_data:
            cmd_total += len(cmd_data)
            detailed_lines.append("💣 Command Injection:")
            for vuln in cmd_data:
                form = vuln.get("form_action", "unknown")
                data = vuln.get("data", {})
                detailed_lines.append(f" - Form: {form} | Payload: {data}")

        # Directory Traversal Scanner
        dir_vulns = entry.get("directory_traversal", {}).get("vulnerabilities", [])
        if dir_vulns:
            section += '<div class="vuln-type">📂 Directory Traversal:</div>'
            for vuln in dir_vulns:
                section += f'<div class="payload">Param: {vuln.get("parameter")} | Payload: {vuln.get("payload")}</div>'


        # CSRF Issues
        csrf_data = entry.get("csrf", {}).get("issues", [])
        if csrf_data:
            csrf_total += len(csrf_data)
            detailed_lines.append("🛑 CSRF Issues:")
            for issue in csrf_data:
                detailed_lines.append(f" - {issue}")

        # Missing Security Headers
        headers = entry.get("headers", {})
        missing_headers = headers.get("missing", [])
        if missing_headers:
            misconfig_total += 1
            detailed_lines.append("🛡️ Missing Security Headers:")
            for h in missing_headers:
                detailed_lines.append(f" - {h}")

        detailed_lines.append("=" * 60)

    # Summary (comes first)
    report_lines.append("🔐 Summary:")
    report_lines.append(f" - URLs scanned: {url_count}")
    report_lines.append(f" - XSS found: {xss_total}")
    report_lines.append(f" - SQL Injection found: {sqli_total}")
    report_lines.append(f" - Command Injection found: {cmd_total}")
    report_lines.append(f" - CSRF issues found: {csrf_total}")
    report_lines.append(f" - Sites with missing security headers: {misconfig_total}")
    report_lines.append("=" * 60)

    # Combine sections
    final_report = "\n".join(report_lines + detailed_lines)

    # Write to file
    try:
        with open(output_file, "w") as out:
            out.write(final_report)
        print(f"✅ Report generated: {output_file}")
    except Exception as e:
        print(f"[!] Error writing to file: {e}")

# CLI entry point
if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python report_generator.py <results.json> [optional_output.txt]")
    else:
        input_file = sys.argv[1]
        output_file = sys.argv[2] if len(sys.argv) > 2 else None
        generate_text_report(input_file, output_file)

