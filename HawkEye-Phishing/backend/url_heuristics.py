import re
from urllib.parse import urlparse

RISKY_TLDS = {"tk", "ml", "ga", "cf", "gq", "xyz", "pw"}

SHORTENER_HOSTS = {
    "bit.ly","tinyurl.com","t.co","goo.gl","shorte.st","buff.ly","ow.ly","is.gd","cutt.ly","bitly.com"
}

def extract_urls_from_text(text: str):
    pattern = r'(https?://[^\s<>\'"]+|www\.[^\s<>\'"]+)'
    return re.findall(pattern, text or "")

def basic_heuristics(url: str):
    reasons = []
    parsed = urlparse(url if url.startswith("http") else "http://" + url)
    host = (parsed.netloc or "").lower()
    host_only = host.split(":")[0]

    # 1) IP as host
    if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", host_only):
        reasons.append("ip_in_host")

    # 2) Very long URL
    if len(url) > 200:
        reasons.append("very_long_url")

    # 3) Encoded / suspicious characters
    if re.search(r"%[0-9A-Fa-f]{2}", url) or "@" in url:
        reasons.append("encoded_chars")

    # 4) Many subdomains
    if host_only.count(".") > 3 or host_only.count("-") > 3:
        reasons.append("weird_subdomain_pattern")

    # 5) Shortener host
    if host_only.replace("www.", "") in SHORTENER_HOSTS:
        reasons.append("url_shortener")

    # 6) Punycode (IDN)
    if "xn--" in host_only:
        reasons.append("punycode_detected")

    # 7) TLD risk
    tld = host_only.split(".")[-1]
    if tld in RISKY_TLDS:
        reasons.append("risky_tld")

    # 8) Common phishing keywords
    for word in ["login","secure","update","verify","account","bank","password"]:
        if word in url.lower():
            reasons.append(f"keyword_{word}")

    return reasons
