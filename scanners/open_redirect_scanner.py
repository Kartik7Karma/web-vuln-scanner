import requests
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from payloads.payloads import open_redirect_payloads, redirect_param_names

import requests
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from payloads.payloads import open_redirect_payloads, redirect_param_names

def open_redirect_scan(url):
    results = []
    parsed = urlparse(url)
    query = parse_qs(parsed.query)

    for param in query:
        if param.lower() in redirect_param_names():
            for payload in open_redirect_payloads():
                # Replace original query with payload
                new_query = query.copy()
                new_query[param] = [payload]

                modified_query = urlencode(new_query, doseq=True)
                modified_url = urlunparse(parsed._replace(query=modified_query))

                try:
                    response = requests.get(modified_url, allow_redirects=False, timeout=10)
                    location = response.headers.get("Location", "")

                    if payload in location:
                        results.append({
                            "parameter": param,
                            "payload": payload,
                            "payload_url": modified_url,
                            "redirected_to": location
                        })

                except requests.RequestException:
                    continue  # Optional: log errors if needed

    return results

