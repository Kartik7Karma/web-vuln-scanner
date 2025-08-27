import time
import requests
import logging
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from payloads.payloads import blind_sqli_payloads  # ✅ Updated usage

logger = logging.getLogger(__name__)

def inject_payload(url, param, payload):
    parsed = urlparse(url)
    query = parse_qs(parsed.query)

    if param not in query:
        return None

    query[param] = payload
    new_query = urlencode(query, doseq=True)
    injected = parsed._replace(query=new_query)
    return urlunparse(injected)

def run(url, session=None, timeout=3, delay_threshold=2, **kwargs):
    session = session or requests.Session()
    parsed = urlparse(url)
    query_params = parse_qs(parsed.query)

    if not query_params:
        logger.warning("[⏩] Blind SQLi skipped: No query parameters in URL.")
        return {
            "scanner": "blind_sqli",
            "status": "skipped",
            "reason": "No query parameters in URL"
        }

    findings = []
    slow_responses = []

    logger.info(f"[🔍] Starting Blind SQLi scan on: {url}")
    logger.info(f"[📌] Testing parameters: {', '.join(query_params.keys())}")

    for param in query_params:
        for payload in blind_sqli_payloads():
            test_url = inject_payload(url, param, payload)
            if not test_url:
                continue

            try:
                logger.debug(f"[⏳] Testing payload on '{param}': {payload}")
                start = time.time()
                response = session.get(test_url, timeout=timeout)
                duration = time.time() - start

                slow_responses.append((payload, round(duration, 2)))

                if duration >= delay_threshold:
                    logger.warning(f"[‼️] Blind SQLi delay detected on '{param}' with payload: {payload} ({duration:.2f}s)")
                    findings.append({
                        "parameter": param,
                        "payload": payload,
                        "response_time": round(duration, 2)
                    })
                    break  # Stop after first success on this param

            except requests.RequestException as e:
                logger.debug(f"[!] Request failed for payload: {payload} → {e}")
                continue

    if findings:
        logger.info(f"[🚨] Blind SQLi vulnerabilities found: {len(findings)}")
    else:
        logger.info(f"[✅] No Blind SQLi vulnerabilities detected.")

    # Top 5 slowest responses for debugging
    if slow_responses:
        top_slow = sorted(slow_responses, key=lambda x: x[1], reverse=True)[:5]
        logger.debug("[📉] Top 5 slowest payloads:")
        for payload, delay in top_slow:
            logger.debug(f"    {delay:.2f}s → {payload}")

    return {
        "scanner": "blind_sqli",
        "status": "vulnerable" if findings else "safe",
        "details": findings
    }
