import requests
from urllib.parse import urlparse

SHORTENER_HOSTS = {
    "bit.ly","tinyurl.com","t.co","goo.gl","shorte.st","buff.ly","ow.ly","is.gd","cutt.ly","bitly.com"
}

def is_shortener_host(host: str):
    return (host or "").replace("www.", "").lower() in SHORTENER_HOSTS

def expand_url_if_shortener(url: str, timeout: int = 6) -> str:
    try:
        parsed = urlparse(url if url.startswith("http") else "http://" + url)
        host = parsed.netloc or ""
        if not is_shortener_host(host):
            return url
        session = requests.Session()
        resp = session.head(url, allow_redirects=True, timeout=timeout)
        final = getattr(resp, "url", None) or url
        if final == url:
            resp = session.get(url, allow_redirects=True, timeout=timeout)
            final = getattr(resp, "url", None) or url
        return final
    except Exception:
        return url
