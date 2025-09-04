import csv
import os
from datetime import datetime

def generate_csv_report(results_data, output_file=None):
    if output_file is None:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_file = f"scan_report_{timestamp}.csv"

    rows = []

    for entry in results_data:
        url = entry.get("url", "unknown")

        # XSS
        for vuln in entry.get("xss", {}).get("vulnerabilities", []):
            rows.append({
                "URL": url,
                "Type": "XSS",
                "Payload": vuln.get("payload", ""),
                "Location": vuln.get("location", "")
            })

        # SQL Injection
        for vuln in entry.get("sql_injection", {}).get("vulnerabilities", []):
            rows.append({
                "URL": url,
                "Type": "SQL Injection",
                "Payload": vuln.get("payload", ""),
                "Location": vuln.get("location", "")
            })

        # Command Injection
        for vuln in entry.get("cmd_injection", {}).get("vulnerabilities", []):
            rows.append({
                "URL": url,
                "Type": "Command Injection",
                "Payload": str(vuln.get("data", "")),
                "Location": vuln.get("form_action", "")
            })
            
        # Directory Traversal
        dir_trav = entry.get("directory_traversal", [])
        if dir_trav:
            section += '<div class="vuln-type">🗂️ Directory Traversal:</div>'
            for vuln in dir_trav:
                section += f'<div class="payload">Payload: {vuln.get("payload")}<br>URL: {vuln.get("url")}</div>'

        # CSRF
        for issue in entry.get("csrf", {}).get("issues", []):
            rows.append({
                "URL": url,
                "Type": "CSRF",
                "Payload": issue,
                "Location": ""
            })

        # Missing Headers
        for header in entry.get("headers", {}).get("missing", []):
            rows.append({
                "URL": url,
                "Type": "Missing Header",
                "Payload": header,
                "Location": ""
            })

    # Write to CSV
    try:
        with open(output_file, mode="w", newline="") as csvfile:
            fieldnames = ["URL", "Type", "Payload", "Location"]
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(rows)

        print(f"✅ CSV report saved as {output_file}")
    except Exception as e:
        print(f"[!] Error writing CSV: {e}")
