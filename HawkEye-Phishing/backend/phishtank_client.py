import requests

PHISHTANK_CHECK_URL = "https://check.phishtank.org/checkurl/"

def check_phishtank(url: str, api_key: str = ""):
    """
    Optional PhishTank lookup. Works offline if no API key provided.
    Returns a simple dict; never raises.
    """
    if not api_key:
        return {"in_database": False, "note": "PhishTank disabled (no API key)"}
    try:
        payload = {"url": url, "format": "json", "app_key": api_key}
        r = requests.post(PHISHTANK_CHECK_URL, data=payload, timeout=8)
        r.raise_for_status()
        j = r.json()
        results = j.get("results", {})
        return {
            "in_database": bool(results.get("in_database")),
            "valid": results.get("valid"),
            "phish_id": results.get("phish_id"),
        }
    except Exception as e:
        return {"in_database": False, "error": str(e)}
