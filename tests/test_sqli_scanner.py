from scanners.sqli_scanner import sql_injection_scan
from unittest.mock import patch, Mock
import pytest

# Mock form structure returned by form_details()
mock_form_details = {
    "action": "/test",
    "method": "get",
    "inputs": [
        {"type": "text", "name": "username", "value": ""},
        {"type": "password", "name": "password", "value": ""},
        {"type": "submit", "name": "submit", "value": "Login"},
    ],
}

# Fake form element
mock_form_element = "<form></form>"


@patch("scanners.sqli_scanner.form_details", return_value=mock_form_details)
@patch("scanners.sqli_scanner.get_forms", return_value=[mock_form_element])
@patch("scanners.sqli_scanner.sqli_payloads", return_value=["' OR 1=1 --"])
@patch("scanners.sqli_scanner.Session.get")
def test_sql_injection_detects_vuln(mock_get, mock_payloads, mock_get_forms, mock_form_details):
    # Simulate a vulnerable response
    mock_response = Mock()
    mock_response.status_code = 200
    mock_response.content = b"You have an error in your SQL syntax"
    mock_get.return_value = mock_response

    url = "http://example.com/login"
    result = sql_injection_scan(url)

    assert isinstance(result, dict)
    assert result["vulnerable"] is True
    assert len(result["vulnerabilities"]) > 0
    assert any(v["payload"] == "' OR 1=1 --" for v in result["vulnerabilities"])



@patch("scanners.sqli_scanner.form_details", return_value=mock_form_details)
@patch("scanners.sqli_scanner.get_forms", return_value=[mock_form_element])
@patch("scanners.sqli_scanner.sqli_payloads", return_value=["' OR 1=1 --"])
@patch("scanners.sqli_scanner.Session.get")
def test_sql_injection_safe_form(mock_get, mock_payloads, mock_get_forms, mock_form_details):
    # Simulate a non-vulnerable response
    mock_response = Mock()
    mock_response.status_code = 200
    mock_response.content = b"Welcome back, user!"
    mock_get.return_value = mock_response

    url = "http://example.com/login"
    result = sql_injection_scan(url)

    assert isinstance(result, dict)
    assert result["vulnerable"] is False
    assert result["vulnerabilities"] == []
