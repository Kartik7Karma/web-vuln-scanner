import requests
import logging
from urllib.parse import urljoin
from core.forms import get_forms, form_details
from payloads.payloads import sqli_payloads
from requests import Session

logger = logging.getLogger(__name__)

def vulnerable(response):
    errors = {
        "you have an error in your sql syntax",
        "warning: mysql",
        "unclosed quotation mark",
        "quoted string not properly terminated",
        "mysql_fetch",
        "syntax error",
        "sqlstate",
        "odbc",
        "invalid query",
    }
    try:
        content = response.content.decode().lower()
    except Exception:
        return False
    return any(error in content for error in errors)

def sql_injection_scan(url):
    s = Session()
    vulnerabilities = []

    try:
        s.get(url, timeout=10).raise_for_status()
    except requests.exceptions.RequestException as e:
        logger.error(f"[!] Error fetching {url}: {e}")
        return {"vulnerable": False, "vulnerabilities": []}

    forms = get_forms(url)
    logger.info(f"[+] Detected {len(forms)} forms on {url}.")

    for form in forms:
        details = form_details(form)
        form_vulns = []

        for payload in sqli_payloads():
            data = {}
            for input_tag in details["inputs"]:
                if input_tag["type"] == "hidden" or input_tag["value"]:
                    data[input_tag["name"]] = input_tag["value"] + payload
                elif input_tag["type"] != "submit":
                    data[input_tag["name"]] = f"test{payload}"

            target_url = urljoin(url, details["action"])
            try:
                if details["method"].lower() == "post":
                    res = s.post(target_url, data=data, timeout=10)
                else:
                    res = s.get(target_url, params=data, timeout=10)
            except requests.exceptions.RequestException as e:
                logger.error(f"[!] Error sending payload to {target_url}: {e}")
                continue

            if vulnerable(res):
                logger.warning(f"[!!!] SQL injection vulnerability in {target_url} | payload: {payload}")
                form_vulns.append({
                    "url": target_url,
                    "form_action": details["action"],
                    "method": details["method"].upper(),
                    "payload": payload
                })

        if form_vulns:
            vulnerabilities.extend(form_vulns)

    return {
        "vulnerable": len(vulnerabilities) > 0,
        "vulnerabilities": vulnerabilities
    }
