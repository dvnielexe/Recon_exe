import requests

def normalize_target(target: str) -> str:
    target = target.strip()

    if target.startswith("http://"):
        target = target[7:]

    elif target.startswith("https://"):
        target = target[8:]

    return target.rstrip("/")

def check_url(url):
    try:
        response = requests.get(
            url,
            timeout=5,
            allow_redirects=False
            )

        security_headers = {
          header: response.headers.get(header)
          for header in [
                "Strict-Transport-Security",
                "Content-Security-Policy",
                "X-Frame-Options",
                "X-Content-Type-Options",
                "Referrer-Policy",
          ]
          if response.headers.get(header) is not None
        }


        return{
            "url": response.url,
            "status_code": response.status_code,
            "is_redirect": response.is_redirect,
            "server": response.headers.get("Server"),
            "content-type": response.headers.get("Content-Type"),
            "redirect": response.headers.get("Location"),
            "security_headers": security_headers,
        }

    except requests.RequestException as e:
        return{
            "url": url,
            "error": str(e),
        }


def scan(target: str) -> dict:
    target = normalize_target(target)

    http_url = f"http://{target}"
    https_url = f"https://{target}"

    return {
        "http": check_url(http_url),
        "https": check_url(https_url),
    }