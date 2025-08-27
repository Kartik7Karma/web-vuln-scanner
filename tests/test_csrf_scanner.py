from scanners.csrf_scanner import scan_csrf
from unittest.mock import patch
import pytest

# Fake forms for testing

# Case 1: POST form with NO CSRF token
post_form_no_token = {
    "method": "POST",
    "inputs": [
        {"type": "hidden", "name": "user_id", "value": "123"},
        {"type": "submit", "name": "submit", "value": "Send"}
    ]
}

# Case 2: POST form WITH CSRF token
post_form_with_token = {
    "method": "POST",
    "inputs": [
        {"type": "hidden", "name": "csrf_token", "value": "abc123"},
        {"type": "submit", "name": "submit", "value": "Send"}
    ]
}

# Case 3: GET form (no CSRF protection expected, but may be flagged)
get_form = {
    "method": "GET",
    "inputs": [
        {"type": "text", "name": "search", "value": ""},
        {"type": "submit", "name": "submit", "value": "Go"}
    ]
}

mock_form_detail = {
    "action": "/fake",
    "method": "POST",
    "inputs": post_form_no_token["inputs"]
}


@patch("scanners.csrf_scanner.form_details", return_value=mock_form_detail)
@patch("scanners.csrf_scanner.get_forms", return_value=[post_form_no_token])
@patch("scanners.csrf_scanner.csrf_token_names", return_value=["csrf_token", "authenticity_token"])
def test_csrf_detects_missing_token(mock_names, mock_get_forms, mock_form_details):
    url = "http://example.com/submit"
    results = scan_csrf(url)

    assert isinstance(results, list)
    assert len(results) == 1
    assert results[0]["method"].lower() == "post"
    assert any(inp["name"] == "user_id" for inp in results[0]["inputs"])


@patch("scanners.csrf_scanner.form_details", return_value={})
@patch("scanners.csrf_scanner.get_forms", return_value=[post_form_with_token])
@patch("scanners.csrf_scanner.csrf_token_names", return_value=["csrf_token", "authenticity_token"])
def test_csrf_safe_form_with_token(mock_names, mock_get_forms, mock_form_details):
    url = "http://example.com/secure"
    results = scan_csrf(url)

    assert isinstance(results, list)
    assert len(results) == 0  # No vulnerabilities detected


@patch("scanners.csrf_scanner.form_details", return_value={})
@patch("scanners.csrf_scanner.get_forms", return_value=[get_form])
@patch("scanners.csrf_scanner.csrf_token_names", return_value=["csrf_token", "authenticity_token"])
def test_csrf_get_form_flagged(mock_names, mock_get_forms, mock_form_details):
    url = "http://example.com/search"
    results = scan_csrf(url, check_get_forms=True)

    # Should not return it as a vulnerability, but logger might show info
    assert isinstance(results, list)
    assert len(results) == 0
