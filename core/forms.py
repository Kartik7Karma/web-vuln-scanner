# forms.py
import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin
from core.utils import extract_links

# Persistent session used across scanners
s = requests.Session()

def get_forms(url):
    """Extract all form tags from a URL."""
    try:
        res = s.get(url, timeout=10)
        soup = BeautifulSoup(res.content, "html.parser")
        return soup.find_all("form")
    except Exception as e:
        print(f"[!] Error getting forms from {url}: {e}")
        return []

def form_details(form):
    """Extract useful form details from a form HTML element."""
    details = {}
    action = form.attrs.get("action", "").strip()
    method = form.attrs.get("method", "get").lower()
    inputs = []

    for input_tag in form.find_all("input"):
        input_type = input_tag.attrs.get("type", "text")
        input_name = input_tag.attrs.get("name")
        input_value = input_tag.attrs.get("value", "")
        inputs.append({"type": input_type, "name": input_name, "value": input_value})

    details["action"] = action
    details["method"] = method
    details["inputs"] = inputs
    return details
