import requests

missing = []
present = {}

def check_headers(headers , scan_results):
    expected = ['Strict-Transport-Security' , 'X-Frame-Options' , 'Content-Security-Policy' , 'X-Content-Type-Options' , 'Permissions-Policy' , 'Referrer-Policy']
    for h in expected:
        if h not in headers:
            print(f' {h} not in the response headers')
            missing.append(h)
        else:
            print(f' {h}: {headers[h]}')
            present[h] = headers[h]

    scan_results["headers"] = {
        "missing": missing,
        "present": present
    }

def check_cookies(response, scan_results):
    cookie_details = []

    # Pull all Set-Cookie headers
    set_cookie_headers = response.headers.get("Set-Cookie")
    if not set_cookie_headers:
        print("No Set-Cookie headers found.")
        scan_results["cookies"] = []
        return

    # Handle multiple cookies in one header
    cookies = set_cookie_headers.split(',')

    for raw_cookie in cookies:
        raw_cookie = raw_cookie.strip()
        name = raw_cookie.split('=')[0]
        issues = []

        if "Secure" not in raw_cookie:
            print("Secure flag missing.")
            issues.append("Secure flag missing.")
        if "HttpOnly" not in raw_cookie:
            print("HttpOnly flag missing.")
            issues.append("HttpOnly flag missing.")
        if "SameSite" not in raw_cookie:
            print("SameSite flag missing.")
            issues.append("SameSite flag missing.")

        if not issues:
            print(f"✅ All flags present for cookie: {name}")
        else:
            for issue in issues:
                print(f"❌ {issue} on cookie: {name}")

        cookie_details.append({
            "name": name,
            "secure": "Secure" in raw_cookie,
            "httponly": "HttpOnly" in raw_cookie,
            "samesite": "SameSite" in raw_cookie,
            "issues": issues
        })

    scan_results["cookies"] = cookie_details

