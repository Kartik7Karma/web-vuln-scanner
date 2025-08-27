import requests
from urllib.parse import urljoin
from concurrent.futures import ThreadPoolExecutor

def scan_misconfigurations(base_url, paths, timeout=5):
    findings = []

    def check_path(path):
        full_url = urljoin(base_url.rstrip("/") + "/", path.lstrip("/"))
        try:
            res = requests.get(full_url, timeout=timeout, allow_redirects=True)
            if res.status_code in [200, 401, 403]:
                return {"path": path, "url": full_url, "status": res.status_code}
        except requests.RequestException:
            return None

    with ThreadPoolExecutor(max_workers=10) as executor:
        results = executor.map(check_path, paths)

    return [r for r in results if r is not None]
