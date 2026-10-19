from urllib.parse import urlsplit, urlunsplit, urljoin
from urllib.parse import parse_qs
from html.parser import HTMLParser
import requests

def normalize_url(url: str) -> str:
    """Normalize basic url components without removing query parameters"""

    url = url.strip()
    parts = urlsplit(url)

    scheme = parts.scheme.lower()
    hostname = (parts.hostname or "").lower()

    if not scheme or not hostname:
        raise ValueError(f"Invalid absolute url: {url}")

    # Preserve a non default port.
    port = parts.port
    if port is not None:
        default_port = (
            (scheme == "http" and port == 80)
            or (scheme == "https" and port == 443)
        )

        netloc = hostname if default_port else f"{hostname}:{port}"
    else:
        netloc = hostname

    path = parts.path or "/"

    return urlunsplit((
        scheme,
        netloc,
        path,
        parts.query,
        "", # Fragments are client side and are not sent in http requests
    ))


def identify_parameters(url: str) -> dict:
    """Extract query parameter names and values from a URL."""
    query = urlsplit(url).query
    parameters = parse_qs(query, keep_blank_values=True)

    return parameters

def extract_endpoint(url: str) -> str:
    """Extract the path component from an absolute url"""

    parts = urlsplit(url)

    if not parts.scheme or not parts.netloc:
        raise ValueError(f"Invalid Absolute URL: {url}")

    return parts.path or "/"

class LinkParser(HTMLParser):
    """Collect href values from HTML anchor tags."""

    def __init__(self):
        super().__init__()
        self.links = []

    def handle_starttag(self, tag, attrs):
        if tag.lower() == "a":
            for name, value in attrs:
                if name.lower() == "href" and value:
                    self.links.append(value)
                    break

def _origin(url: str) -> tuple:
    """Return the normalized origin of a URL."""

    parts = urlsplit(url)
    scheme = parts.scheme.lower()
    hostname = (parts.hostname or "").lower()

    if not scheme or not hostname:
        raise ValueError(f"Invalid absolute URL: {url}")

    port = parts.port

    if port is None:
        port = 80 if scheme == "http" else 443 if scheme == "https" else None

    return scheme, hostname, port


def collect_urls(
    start_url: str,
    max_urls: int = 100,
    timeout: float = 5.0,
) -> list:
    """Collect same-origin links from one HTML page."""
    if max_urls < 1:
        raise ValueError("max_urls must be at least 1")

    start_url = normalize_url(start_url)

    if urlsplit(start_url).scheme not in ("http", "https"):
        raise ValueError("Only HTTP and HTTPS URLs are supported")

    response = requests.get(
        start_url,
        timeout=timeout,
        allow_redirects=False,
    )
    response.raise_for_status()

    content_type = response.headers.get("Content-Type", "").lower()


    if "text/html" not in content_type:
        return []

    parser = LinkParser()
    parser.feed(response.text)

    base_origin = _origin(start_url)
    collected = set()

    for href in parser.links:
        absolute_url = urljoin(start_url, href)


        try:
            if _origin(absolute_url) != base_origin:
                continue

            normalized = normalize_url(absolute_url)
        except ValueError:
            continue

        if normalized not in collected:
            collected.add(normalized)

        if len(collected) >= max_urls:
            break

    return sorted(collected)


def scan(target: str, max_urls: int = 100) -> dict:
    """Run URL intelligence against a starting URL"""
    target = target.strip()

    if not target.startswith(("http://", "https://")):
        target = f"https://{target}"

    start_url = normalize_url(target)

    collected_urls = collect_urls(start_url, max_urls=max_urls)

    results = []

    # Include the starting URL even if the page has no links
    all_urls = sorted(set(collected_urls) | {start_url})

    results = []

    for url in all_urls:
        results.append({
            "url": url,
            "endpoint": extract_endpoint(url),
            "parameters": identify_parameters(url),
         })

    return {
        "start_url": start_url,
        "urls_found": len(results),
        "results": results,
    }