import json
from datetime import datetime
from pathlib import Path

# HTML template with basic styling and placeholders
HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Web Vulnerability Report</title>
    <style>
        body {{
            font-family: Arial, sans-serif;
            background-color: #f2f2f2;
            padding: 20px;
        }}
        h1, h2 {{
            color: #2c3e50;
        }}
        .url-section {{
            background-color: white;
            border: 1px solid #ddd;
            border-radius: 6px;
            padding: 15px;
            margin-bottom: 20px;
        }}
        .vuln-type {{
            margin-top: 10px;
            font-weight: bold;
        }}
        .payload {{
            background: #f4f4f4;
            font-family: monospace;
            padding: 6px;
            margin: 5px 0;
        }}
        ul.missing-headers li {{
            color: #c0392b;
        }}
        .summary {{
            background-color: #eafaf1;
            border-left: 6px solid #2ecc71;
            padding: 15px;
            margin-bottom: 25px;
        }}
    </style>
</head>
<body>
    <h1>🔍 Web Vulnerability Scan Report</h1>
    <p><strong>Generated on:</strong> {timestamp}</p>

    <div class="summary">
        <h2>📊 Summary</h2>
        <p>Total URLs Scanned: {url_count}</p>
        <p>Total XSS: {xss_total}</p>
        <p>Total SQL Injection: {sqli_total}</p>
        <p>Total Command Injection: {cmd_total}</p>
        <p>Total CSRF Issues: {csrf_total}</p>
        <p>Sites Missing Security Headers: {headers_missing}</p>
    </div>

    {body}
</body>
</html>
"""

def load_results(json_path):
    """Reads the JSON file and returns parsed Python objects."""
    with open(json_path, "r") as file:
        return json.load(file)

def build_html_body(scan_data):
    """Converts scan result objects into HTML blocks."""
    html_sections = []

    # Stats counters
    xss_total = sqli_total = cmd_total = csrf_total = headers_missing = 0

    # --- MODIFICATION START ---
    # Ensure scan_data is always a list (even if single URL passed)
    if isinstance(scan_data, dict):
        scan_data = [scan_data]
    # --- MODIFICATION END ---

    for entry in scan_data:
        url = entry.get("url", "Unknown URL")
        section = f'<div class="url-section">\n<h2>🔗 {url}</h2>'

        # XSS
        xss_vulns = entry.get("xss_vulnerabilities", [])
        if xss_vulns:
            xss_total += len(xss_vulns)
            section += '<div class="vuln-type">⚡ XSS:</div>'
            for vuln in xss_vulns:
                section += f'<div class="payload">Payload: {vuln.get("payload")}</div>'

        # SQL Injection
        sqli_vulns = entry.get("sql_vulnerabilities", [])
        if sqli_vulns:
            sqli_total += len(sqli_vulns)
            section += '<div class="vuln-type">🧨 SQL Injection:</div>'
            for vuln in sqli_vulns:
                section += f'<div class="payload">Payload: {vuln.get("payload")}</div>'

        # Command Injection
        cmd_vulns = entry.get("cmd_injection", {}).get("vulnerabilities", [])
        if cmd_vulns:
            cmd_total += len(cmd_vulns)
            section += '<div class="vuln-type">💣 Command Injection:</div>'
            for vuln in cmd_vulns:
                section += f'<div class="payload">Payload: {vuln.get("data")}</div>'

        # Directory Traversal
        dir_trav = entry.get("directory_traversal", [])
        if dir_trav:
            section += '<div class="vuln-type">🗂️ Directory Traversal:</div>'
            for vuln in dir_trav:
                section += f'<div class="payload">Payload: {vuln.get("payload")}<br>URL: {vuln.get("url")}</div>'

        # CSRF
        csrf_vulns = entry.get("csrf", {}).get("vulnerabilities", [])
        if csrf_vulns:
            csrf_total += len(csrf_vulns)
            section += '<div class="vuln-type">🔓 CSRF:</div>'
            for vuln in csrf_vulns:
                section += f'<div class="payload">Form Action: {vuln.get("form_action")}</div>'

        # Missing Security Headers
        headers = entry.get("headers", {}).get("missing", [])
        if headers:
            headers_missing += 1
            section += '<div class="vuln-type">🛡️ Missing Security Headers:</div><ul class="missing-headers">'
            for header in headers:
                section += f'<li>{header}</li>'
            section += '</ul>'

        section += '</div>'  # Close .url-section
        html_sections.append(section)

    return html_sections, {
        "xss_total": xss_total,
        "sqli_total": sqli_total,
        "cmd_total": cmd_total,
        "csrf_total": csrf_total,
        "headers_missing": headers_missing,
        "url_count": len(scan_data)
    }

def generate_html_report(results):
    """Creates the final HTML report as a string."""
    body_blocks, stats = build_html_body(results)

    final_html = HTML_TEMPLATE.format(
        timestamp=datetime.now().strftime("%Y-%m-%d %H:%M"),
        body="\n".join(body_blocks),
        **stats
    )

    return final_html

def save_html(content, filename="report.html"):
    """Writes the HTML content to a file."""
    with open(filename, "w") as f:
        f.write(content)
    print(f"[✓] HTML report saved as {filename}")

if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print("Usage: python html_report_generator.py results.json")
        sys.exit(1)

    json_path = sys.argv[1]
    try:
        results = load_results(json_path)
        html = generate_html_report(results)
        save_html(html)
    except Exception as e:
        print(f"[!] Failed to generate report: {e}")
