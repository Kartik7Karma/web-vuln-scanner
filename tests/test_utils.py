from core.utils import extract_links

def test_extract_links_from_html():
    html = """
    <html>
      <body>
        <a href="/home">Home</a>
        <a href="http://example.com/about">About</a>
        <a href="#contact">Contact</a>
      </body>
    </html>
    """
    base_url = "http://example.com"

    links = extract_links(html, base_url)

    assert isinstance(links, list)
    assert "http://example.com/home" in links
    assert "http://example.com/about" in links
    assert "http://example.com#contact" in links
    assert len(links) == 3
