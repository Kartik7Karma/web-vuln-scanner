import json

def normalize_scan_result(result):
    return {
        "url": result.get("url", ""),
        "headers": {
            "missing": result.get("headers", {}).get("missing", []),
            "present": result.get("headers", {}).get("present", {})
        },
        "cookies": result.get("cookies", {
            "missing_flags": [],
            "secure_flags": False
        }),
        "forms": result.get("forms", []),
        "xss": {
            "reflected": bool(result.get("xss_vulnerabilities")),
            "vulnerabilities": result.get("xss_vulnerabilities", [])
        },
        "sqli": {
            "vulnerable": bool(result.get("sql_vulnerabilities")),
            "vulnerabilities": result.get("sql_vulnerabilities", [])
        },
        "cmd_injection": {
            "vulnerable": result.get("cmd_injection", {}).get("vulnerable", False),
            "vulnerabilities": result.get("cmd_injection", {}).get("vulnerabilities", [])
        },
        "open_redirect": result.get("open_redirect", {
            "vulnerable": False,
            "vulnerabilities": []
        }),
        "errors": result.get("errors", []) if "errors" in result else ([result["error"]] if "error" in result else [])
    }

def save_results_to_json(all_results, filename="scan_results.json"):
    normalized = [normalize_scan_result(r) for r in all_results]
    with open(filename, "w", encoding="utf-8") as f:
        json.dump(normalized, f, indent=4, sort_keys=True, ensure_ascii=False)
    print(f"[+] Results written to {filename}")

