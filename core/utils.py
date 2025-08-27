# utils.py
from bs4 import BeautifulSoup
from urllib.parse import urljoin

def extract_links(html_content, base_url):
    """Extract and normalize all anchor tag links."""
    soup = BeautifulSoup(html_content, "html.parser")
    links = set()
    for tag in soup.find_all("a", href=True):
        link = urljoin(base_url, tag['href'])
        links.add(link)
    return list(links)
