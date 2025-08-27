import logging
from payloads.payloads import csrf_token_names
from core.forms import get_forms, form_details

logger = logging.getLogger(__name__)

def scan_csrf(url, check_get_forms=False):
    potential_vulnerabilities = []
    forms = get_forms(url)

    for form in forms:
        method = form.get("method", "get").lower()
        inputs = form.get("inputs", [])

        if method == "post":
            has_token = any(
                inp.get("type") == "hidden" and inp.get("name", "").lower() in csrf_token_names()
                for inp in inputs
            )
            if not has_token:
                logger.warning(f"[!] CSRF token missing in POST form on {url}")
                logger.debug(f"[*] Form details: {form}")
                potential_vulnerabilities.append(form_details(form))

        elif check_get_forms:
            # Optional: flag GET forms for manual review
            logger.info(f"[~] GET form found on {url} (manual CSRF check recommended).")
            logger.debug(f"[*] GET form details: {form_details(form)}")

    return potential_vulnerabilities
