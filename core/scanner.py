import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

import requests
import argparse
import logging
import json
import multiprocessing
from concurrent.futures import ThreadPoolExecutor

from core.logger import setup_logger
from core.forms import get_forms, form_details,s
from scanners.headers_cookies_check import check_headers, check_cookies
from scanners.sqli_scanner import sql_injection_scan
from scanners.xss_scanner import scan_xss
from scanners.open_redirect_scanner import open_redirect_scan
from scanners.cmd_injection_scanner import command_injection_scan
from scanners.misconfiguration_scanner import scan_misconfigurations
from scanners.csrf_scanner import scan_csrf
from scanners.blind_sqli_scanner import run as blind_sqli_run
from scanners.dom_xss_scanner import run as dom_xss_run
from scanners.directory_traversal import test_directory_traversal
from reports.output_utils import save_results_to_json
from reports.html_report_generator import generate_html_report, save_html
from reports.csv_report_generator import generate_csv_report
from reports.text_report_generator import generate_text_report
from payloads.payloads import (
    xss_payloads,
    sqli_payloads,
    command_injection_basic_payloads,
    command_injection_advanced_payloads,
    misconfiguration_paths
)

logger = logging.getLogger(__name__)
url_to_scan = "http://testphp.vulnweb.com"

def format_result(vulns):
    return {"vulnerable": bool(vulns), "vulnerabilities": vulns or []}

def scan_url(url):
    logger.info(f"\U0001F4E1 Scanning the {url}")
    scan_results = {"url": url, "errors": []}

    try:
        response = requests.get(url, timeout=10)
        check_headers(response.headers, scan_results)
        check_cookies(response, scan_results)
    except requests.exceptions.RequestException as e:
        logger.error(f"\u274C Failed to scan {url}: {e}")
        scan_results["errors"].append(str(e))

    return scan_results

def load_urls_from_file(file_path):
    try:
        with open(file_path, 'r') as f:
            return [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        logger.error(f"\u274C File not found: {file_path}")
        return []

def run_all_test_scanners(
    url,
    use_basic_cmd=True,
    use_advanced_cmd=False,
    check_misconfig=False,
    check_csrf=False,
    check_blind_sqli=False,
    check_dom_xss=False,
    check_dir_traversal=False
):
    logger.info(f"\n🔍 Running all scanners on: {url}\n")
    result = scan_url(url)

    # 1. Detect HTML forms on the page
    forms = get_forms(url)
    result["forms"] = [form_details(form) for form in forms]
    logger.info(f"[+] Detected {len(result['forms'])} forms.")

    # 2. SQL Injection Scanner
    sqli_vulns = sql_injection_scan(url)
    result["sqli"] = {
    "vulnerable": bool(sqli_vulns.get("vulnerabilities")),
    "vulnerabilities": sqli_vulns.get("vulnerabilities", [])
}
    logger.info(f"[!] SQLi vulnerabilities found: {len(sqli_vulns.get('vulnerabilities', []))}" 
            if sqli_vulns.get('vulnerabilities') else "[✓] No SQL injection found.")

    # 3. XSS Scanner (Reflected)
    xss_vulns = scan_xss(url)
    result["xss"] = {
    "vulnerable": bool(xss_vulns),
    "vulnerabilities": xss_vulns
}
    logger.info(f"[!] XSS vulnerabilities found: {len(xss_vulns)}" 
            if xss_vulns else "[✓] No XSS vulnerabilities found.")

    # 4. Open Redirect Scanner
    redirect_results = open_redirect_scan(url)
    result["open_redirect"] = {
        "vulnerable": bool(redirect_results),
        "vulnerabilities": redirect_results
    }
    logger.info(f"[!] Open Redirect issues: {len(redirect_results)}" if redirect_results else "[✓] No Open Redirect issues.")

    # 5. Misconfiguration Scanner (optional)
    if check_misconfig:
        misconfig_results = scan_misconfigurations(url, misconfiguration_paths())
        result["misconfigurations"] = misconfig_results
        logger.info(f"[!] Found {len(misconfig_results)} misconfiguration exposures." if misconfig_results else "[✓] No misconfiguration exposures found.")

    # 6. CSRF Scanner (optional)
    if check_csrf:
        csrf_issues = scan_csrf(url)
        result["csrf"] = {
            "vulnerable": bool(csrf_issues),
            "issues": csrf_issues
        }
        logger.info(f"[!] CSRF protection issues found: {len(csrf_issues)}" if csrf_issues else "[✓] CSRF protections appear present.")

    # 7. Blind SQLi Scanner (optional)
    if check_blind_sqli:
        blind_result = blind_sqli_run(url)
        result["blind_sqli"] = blind_result
        logger.info("[!] Blind SQLi found." if blind_result.get("status") == "vulnerable" else "[✓] No Blind SQLi vulnerabilities found.")

    # 8. DOM-based XSS Scanner (optional)
    if check_dom_xss:
        dom_xss_results = dom_xss_run(url)
        result["dom_xss"] = dom_xss_results
        logger.info("[!] DOM XSS vulnerabilities found." if dom_xss_results.get("status") == "vulnerable" else "[✓] No DOM-based XSS vulnerabilities found.")

    # 9. Directory Traversal Scanner (optional)
    if check_dir_traversal:
        dir_trav_vulns = test_directory_traversal(url)
        result["directory_traversal"] = {
            "vulnerable": bool(dir_trav_vulns),
            "vulnerabilities": dir_trav_vulns
        }
        logger.info(f"[!] Directory Traversal vulnerabilities found: {len(dir_trav_vulns)}" if dir_trav_vulns else "[✓] No Directory Traversal issues.")

    # 10. Command Injection Scanner (basic and/or advanced)
    cmd_payloads = []
    if use_basic_cmd:
        cmd_payloads += command_injection_basic_payloads()
    if use_advanced_cmd:
        cmd_payloads += command_injection_advanced_payloads()

    cmd_results = command_injection_scan(url, cmd_payloads)
    result["cmd_injection"] = {
        "vulnerable": bool(cmd_results),
        "vulnerabilities": cmd_results
    }
    logger.info(f"[!] Command Injection found: {len(cmd_results)}" if cmd_results else "[✓] No Command Injection vulnerabilities found.")

    return result


def main():
    parser = argparse.ArgumentParser(description='\U0001F310 WEB VULNERABILITY SCANNER')
    parser.add_argument('--url', help='Scan a single URL')
    parser.add_argument('--url-list', help='Scan multiple URLs from file')
    parser.add_argument('--output-json', metavar='FILENAME', type=str, help='Save output to JSON file')
    parser.add_argument('-v', '--verbose', action='store_true', help='Enable verbose logging')
    parser.add_argument('--cmd-basic', action='store_true', help='Use basic CMD injection payloads')
    parser.add_argument('--cmd-advanced', action='store_true', help='Use advanced CMD injection payloads')
    parser.add_argument('--check-misconfig', action='store_true', help='Check for misconfiguration files/paths')
    parser.add_argument('--check-csrf', action='store_true', help='Check for missing CSRF protection in POST forms')
    parser.add_argument('--check-blind-sqli', action='store_true', help='Check for Blind SQL Injection')
    parser.add_argument('--check-dom-xss', action='store_true', help='Check for DOM-based XSS using headless browser')
    parser.add_argument('--check-dir-traversal', action='store_true', help='Check for Directory Traversal vulnerabilities')
    parser.add_argument('--full-scan', action='store_true', help='Enable all optional vulnerability checks')
    parser.add_argument('--text-report', nargs='?', const='report.txt', help='Generate plain text report (optional filename)')
    parser.add_argument('--html-report', nargs='?', const='report.html', help='Generate styled HTML report (optional filename)')
    parser.add_argument('--csv-report', nargs='?', const='report.csv', help='Generate CSV report (optional filename)')


    args = parser.parse_args()

    setup_logger(level=logging.DEBUG if args.verbose else logging.INFO)

    urls = []
    if args.url:
        urls.append(args.url)
    elif args.url_list:
        urls.extend(load_urls_from_file(args.url_list))
    else:
        logger.warning("No URL provided. Defaulting to test URL.")
        urls.append(url_to_scan)

    use_basic_cmd = args.cmd_basic or not args.cmd_advanced
    use_advanced_cmd = args.cmd_advanced

    check_all = args.full_scan
    check_misconfig = check_all or args.check_misconfig
    check_csrf = check_all or args.check_csrf
    check_blind_sqli = check_all or args.check_blind_sqli
    check_dom_xss = check_all or args.check_dom_xss
    check_dir_traversal = check_all or args.check_dir_traversal

    max_threads = min(32, multiprocessing.cpu_count() * 4)
    with ThreadPoolExecutor(max_workers=max_threads) as executor:
        all_results = list(executor.map(
            lambda u: run_all_test_scanners(
                u,
                use_basic_cmd,
                use_advanced_cmd,
                check_misconfig,
                check_csrf,
                check_blind_sqli,
                check_dom_xss,
                check_dir_traversal
            ),
            urls
        ))
        logger.info("\n✅ Scan complete.")
        print("scan complete")
    if 'results_data' not in locals():
        results_data = all_results

    if args.output_json:
        output_path = args.output_json[0] if isinstance(args.output_json, list) else args.output_json

        save_results_to_json(all_results, output_path)
        logger.info(f"[📁] Results saved to {output_path}")

        try:
            with open(output_path, "r") as f:
                results_data = json.load(f)
        except Exception as e:
            logger.warning(f"[!] Failed to read JSON: {e}")
            results_data = None

    if args.text_report:
        try:
            if results_data is None and args.output_json and os.path.exists(args.output_json):
                with open(args.output_json, "r") as f:
                    results_data = json.load(f)

            if results_data:
                generate_text_report(results_data, args.text_report)
                logger.info(f"[📄] Text report saved to {args.text_report}")
            else:
                logger.error("[!] Cannot generate text report: No data available.")
        except Exception as e:
            logger.error(f"[!] Failed to generate text report: {e}")
 
    if not all_results and args.output_json and os.path.exists(args.output_json):
        try:
            with open(args.output_json, "r") as f:
                results_data = json.load(f)
        except Exception as e:
            logger.error(f"[!] Failed to load JSON for report generation: {e}")
            results_data = None


    if args.html_report:
        html = generate_html_report(results_data)
        save_html(html, args.html_report)

    if args.csv_report:
        generate_csv_report(results_data, args.csv_report)



if __name__ == "__main__":
    main()