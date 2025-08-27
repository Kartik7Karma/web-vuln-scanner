from scanners.xss_scanner import scan_xss
from unittest.mock import patch, Mock

# Fake form structure (text input vulnerable to XSS)
mock_form_details = {
    "action": "/submit",
    "method": "get",
    "inputs": [
        {"type": "text", "name": "comment", "value": ""},
        {"type": "submit", "name": "submit", "value": "Send"}
    ]
}

# Simulated HTML form element (not used deeply, just passed to get_forms)
mock_form = "<form></form>"

# Payloads used for the tests
mock_xss_payloads = ["<script>alert('xss')</script>"]


@patch("scanners.xss_scanner.form_details", return_value=mock_form_details)
@patch("scanners.xss_scanner.get_forms", return_value=[mock_form])
@patch("scanners.xss_scanner.requests.get")
def test_xss_detects_vulnerability(mock_get, mock_get_forms, mock_form_details):
    # Simulate vulnerable response
    mock_response = Mock()
    mock_response.status_code = 200
    mock_response.text = "Welcome <script>alert('xss')</script>"
    mock_get.return_value = mock_response

    url = "http://example.com/page"
    result = scan_xss(url, mock_xss_payloads)

    assert isinstance(result, list)
    assert len(result) > 0
    assert "inputs" in result[0]["form_details"]
    assert any(inp["name"] == "comment" for inp in result[0]["form_details"]["inputs"])


@patch("scanners.xss_scanner.form_details", return_value=mock_form_details)
@patch("scanners.xss_scanner.get_forms", return_value=[mock_form])
@patch("scanners.xss_scanner.requests.get")
def test_xss_safe_form(mock_get, mock_get_forms, mock_form_details):
    # Simulate clean response
    mock_response = Mock()
    mock_response.status_code = 200
    mock_response.text = "Welcome user!"
    mock_get.return_value = mock_response

    url = "http://example.com/page"
    result = scan_xss(url, mock_xss_payloads)

    assert isinstance(result, list)
    assert len(result) == 0  # No vulnerabilities
