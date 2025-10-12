from flask import Flask, request, jsonify
import os
import sqlite3
from urllib.parse import urlparse

# Core analyzers
from url_heuristics import basic_heuristics, extract_urls_from_text
from utils.url_expand import expand_url_if_shortener
from utils.domain_age import domain_age_days
from utils.favicon_checker import check_favicon_similarity
from utils.scoring_v2 import compute_final_score

# Threat feeds
from feeds.local_feed_lookup import check_domain_in_local_feed, ensure_feed_db
from phishtank_client import check_phishtank

from cache import TTLCache

app = Flask(__name__)
CACHE = TTLCache(max_items=10000, ttl_seconds=3600)  # 1h cache

# --- Startup: make sure local feed DB exists ---
ensure_feed_db()

@app.route("/healthz", methods=["GET"])
def health():
    return jsonify({"status": "ok"}), 200


def analyze_single_url(url: str):
    """Full pipeline analysis for one URL."""
    key = url.strip()
    cached = CACHE.get(key)
    if cached is not None:
        return cached

    # 1) Expand shorteners (bit.ly, t.co, etc.)
    resolved_url = expand_url_if_shortener(url)
    resolved_via_expand = (resolved_url != url)

    # 2) Heuristics on the resolved URL
    reasons = basic_heuristics(resolved_url)
    if resolved_via_expand:
        reasons.append("url_shortener_redirected")

    # 3) Parse host
    parsed = urlparse(resolved_url if resolved_url.startswith("http") else "http://" + resolved_url)
    host = (parsed.netloc or "").split(":")[0].lower()

    # 4) Domain age (WHOIS); add "new_domain" if < 90 days
    age_days = domain_age_days(host)
    if age_days is not None and age_days < 90:
        reasons.append("new_domain")

    # 5) Local threat feed lookup (SQLite)
    in_local_feed = check_domain_in_local_feed(host)
    if in_local_feed:
        reasons.append("in_local_feed")

    # 6) Optional: PhishTank online lookup (if API key set)
    in_phishtank = False
    phish_meta = {}
    pkey = os.getenv("PHISHTANK_API_KEY", "")
    if pkey:
        phish_meta = check_phishtank(resolved_url, api_key=pkey) or {}
        if phish_meta.get("in_database"):
            in_phishtank = True
            reasons.append("in_phishtank")

    # 7) Favicon similarity to known brands (possible clones)
    fav = check_favicon_similarity(resolved_url)
    if fav.get("match"):
        reasons.append(f"favicon_like_{fav.get('brand')}")

    # 8) Indicators for scoring
    indicators = {
        "in_feed": bool(in_local_feed or in_phishtank),
        "ml_prob": 0.0,                   # reserved for Phase-ML
        "domain_age_days": age_days,      # informational
        "favicon_brand": fav.get("brand") if fav.get("match") else None,
        "resolved_via_expand": resolved_via_expand
    }

    # 9) Final score / label / confidence
    final = compute_final_score(reasons, indicators)

    result = {
        "input_url": url,
        "resolved_url": resolved_url,
        "resolved_via_expand": resolved_via_expand,
        "host": host,
        "domain_age_days": age_days,
        "score": final["score"],
        "label": final["label"],
        "confidence": final["confidence"],
        "reasons": final["reasons"],
        "indicators": indicators,
        "phishtank": phish_meta,
    }
    CACHE.set(key, result)
    return result


@app.route("/analyze/url", methods=["POST"])
def analyze_url():
    data = request.get_json(force=True, silent=True) or {}
    url = data.get("url")
    if not url:
        return jsonify({"error": "missing url"}), 400
    return jsonify(analyze_single_url(url))


@app.route("/analyze/url/batch", methods=["POST"])
def analyze_url_batch():
    data = request.get_json(force=True, silent=True) or {}
    urls = data.get("urls") or []
    if not isinstance(urls, list) or len(urls) == 0:
        return jsonify({"error": "missing urls list"}), 400
    results = [analyze_single_url(u) for u in urls]
    return jsonify({"results": results})


@app.route("/analyze/text", methods=["POST"])
def analyze_text_for_urls():
    data = request.get_json(force=True, silent=True) or {}
    text = data.get("text", "")
    urls = extract_urls_from_text(text)
    results = [analyze_single_url(u) for u in urls]
    return jsonify({"urls": urls, "results": results})


# Utility: rebuild local feed DB (dev convenience)
@app.route("/feeds/reload", methods=["POST"])
def feeds_reload():
    try:
        ensure_feed_db(force_recreate=True)
        return jsonify({"status": "reloaded"}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)), debug=True)
