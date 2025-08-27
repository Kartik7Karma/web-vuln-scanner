from core.forms import get_forms, form_details
from unittest.mock import patch, Mock
import requests

# Sample HTML containing two forms
html_with_forms = """
<html>
  <body>
    <form action="/submit" method="post">
      <input type="text" name="username" value="">
      <input type="password" name="password">
      <input type="submit" value="Login">
    </form>
    <form action="/search" method="get">
      <input type="search" name="query">
      <input type="submit" value="Search">
    </form>
  </body>
</html>
"""

# Mock response for requests.get
mock_response = Mock()
mock_response.status_code = 200
mock_response.content = html_with_forms.encode()


@patch("core.forms.s.get", return_value=mock_response)
def test_get_forms_extracts_all_forms(mock_get):
    url = "http://example.com"
    forms = get_forms(url)
    
    assert isinstance(forms, list)
    assert len(forms) == 2
    assert forms[0].name == "form"
    assert forms[1].attrs["action"] == "/search"


def test_form_details_extraction():
    from bs4 import BeautifulSoup

    soup = BeautifulSoup(html_with_forms, "html.parser")
    form = soup.find("form")  # First form

    details = form_details(form)

    assert isinstance(details, dict)
    assert details["action"] == "/submit"
    assert details["method"] == "post"
    assert len(details["inputs"]) == 3

    input_names = [inp["name"] for inp in details["inputs"]]
    assert "username" in input_names
    assert "password" in input_names
