import requests
import logging
from urllib.parse import urljoin
from core.forms import get_forms, form_details
from payloads.payloads import xss_payloads  # should return a list of payloads

logger = logging.getLogger(__name__)

def load_payloads(file_path):
    """Load XSS payloads from file."""
    try:
        with open(file_path, 'r') as f:
            return [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        logger.error(f"[!] Payload file not found: {file_path}")
        return []

def scan_xss(url, payloads=None):
    """Scan for XSS vulnerabilities on the given URL."""
    if payloads is None:
        payloads = xss_payloads()
    vulnerabilities = []

    try:
        forms = get_forms(url)
    except Exception as e:
        logger.error(f"[!] Error fetching forms from {url}: {e}")
        return []  # return empty list for consistency

    logger.info(f"[+] Detected {len(forms)} forms on {url}.")

    for form in forms:
        details = form_details(form)
        for payload in payloads:
            logger.debug(f"[!] Testing payload: {payload}")

            data = {}
            for input_tag in details["inputs"]:
                if input_tag["type"] == "hidden" or input_tag["value"]:
                    data[input_tag["name"]] = input_tag["value"] + payload
                elif input_tag["type"] != "submit":
                    data[input_tag["name"]] = f"test{payload}"

            target_url = urljoin(url, details["action"])

            try:
                if details["method"].lower() == "post":
                    response = requests.post(target_url, data=data, timeout=10)
                else:
                    response = requests.get(target_url, params=data, timeout=10)
            except requests.exceptions.RequestException as e:
                logger.error(f"[!] Error sending payload to {target_url}: {e}")
                continue

            if payload in response.text:
                logger.warning(f"[!!!] XSS vulnerability detected on {target_url}")
                vulnerabilities.append({
                    "url": target_url,
                    "form_action": details["action"],
                    "method": details["method"].upper(),
                    "payload": payload,
                    "form_details": details
                })

    
    return vulnerabilities
