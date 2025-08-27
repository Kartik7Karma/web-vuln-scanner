import time
from selenium import webdriver
from selenium.webdriver.firefox.options import Options
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from payloads.payloads import dom_xss_payloads
from selenium.webdriver.firefox.service import Service

from selenium.webdriver.firefox.service import Service
from selenium.webdriver.firefox.options import Options
from selenium import webdriver

def setup_browser():
    options = Options()
    options.binary_location = "/snap/firefox/current/usr/lib/firefox/firefox"
    
    options.add_argument("--headless")
    options.add_argument("--disable-gpu")
    options.add_argument("--no-sandbox")
    service = Service(executable_path="/snap/bin/geckodriver")
    
    # Pass both options and service into Firefox
    driver = webdriver.Firefox(service=service, options=options)
    return driver


def inject_payload(url, param, payload):
    parsed = urlparse(url)
    query = parse_qs(parsed.query)
    if param in query:
        query[param] = payload
        new_query = urlencode(query, doseq=True)
        return urlunparse(parsed._replace(query=new_query))
    return url

def run(url, **kwargs):
    parsed = urlparse(url)
    query_params = parse_qs(parsed.query)

    if not query_params:
        print("[⏩] Skipping DOM XSS (no query parameters found).")
        return {
            "scanner": "dom_xss",
            "status": "skipped",
            "reason": "No query parameters"
        }

    browser = setup_browser()
    payloads = dom_xss_payloads()
    findings = []

    print(f"[🔍] Running DOM XSS scan on: {url}")

    for param in query_params:
        for payload in payloads:
            test_url = inject_payload(url, param, payload)
            try:
                browser.get(test_url)
                time.sleep(2)

                # Detect alert() if triggered
                try:
                    alert = browser.switch_to.alert
                    if "XSS" in alert.text:
                        alert.dismiss()
                        print(f"[🚨] DOM XSS triggered via alert() on '{param}' with payload: {payload}")
                        findings.append({
                            "parameter": param,
                            "payload": payload,
                            "method": "alert()"
                        })
                        break
                except:
                    pass

                # Fallback: Check payload in DOM
                if payload.lower() in browser.page_source:
                    print(f"[‼️] DOM XSS likely via reflection on '{param}' with payload: {payload}")
                    findings.append({
                        "parameter": param,
                        "payload": payload,
                        "method": "reflected"
                    })
                    break

            except Exception as e:
                print(f"[!] Error loading {test_url}: {e}")
                continue

    browser.quit()

    if findings:
        print(f"[🔥] DOM XSS vulnerabilities found: {len(findings)}")
        return {
            "scanner": "dom_xss",
            "status": "vulnerable",
            "details": findings
        }

    print("[✅] No DOM XSS vulnerabilities detected.")
    return {
        "scanner": "dom_xss",
        "status": "safe",
        "details": []
    }
