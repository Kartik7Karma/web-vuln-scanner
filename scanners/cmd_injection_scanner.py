import requests
from urllib.parse import urljoin
from core.forms import get_forms, form_details
from payloads.payloads import is_command_injection_successful
import logging

logger = logging.getLogger(__name__)

def command_injection_scan(url, payloads):
    """Scan all forms on the page for Command Injection using given payloads."""
    results = []
    forms = get_forms(url)

    for form in forms:
        details = form_details(form)
        action = details.get("action")
        method = details.get("method", "get").lower()
        inputs = details.get("inputs", [])

        for payload in payloads:
            data = {}
            for input_field in inputs:
                if input_field["type"] in ["text", "search", "hidden"]:
                    data[input_field["name"]] = payload
                elif input_field["type"] == "submit" and input_field["name"]:
                    data[input_field["name"]] = input_field.get("value", "submit")

            target_url = urljoin(url, action) if action else url

            try:
                if method == "post":
                    res = requests.post(target_url, data=data, timeout=3)
                else:
                    res = requests.get(target_url, params=data, timeout=3)

                # Check for success and find matched indicator
                indicators = ["PING", "TTL=", "bytes from", "icmp_seq=", "time="]
                matched = next((ind for ind in indicators if ind.lower() in res.text.lower()), None)

                if matched:
                    logger.info(f"[!] Command Injection detected at {target_url} with payload: {payload}")
                    results.append({
                        "form_action": action,
                        "target_url": target_url,
                        "payload": payload,
                        "method": method.upper(),
                        "data": data,
                        "status_code": res.status_code,
                        "matched_indicator": matched
                    })
            except requests.RequestException as e:
                logger.debug(f"Request failed for {target_url}: {e}")
                continue

    return results
