import requests, imagehash
from PIL import Image
from io import BytesIO

# Simple demo set — add more brand hashes as needed
KNOWN_BRAND_HASHES = {
    "paypal": "a9f132c41d7f90c3",
    "google": "c2e9d3b8aa12ff10",
}

def check_favicon_similarity(url: str, timeout: int = 6):
    """
    Try to fetch /favicon.ico and compare perceptual hash to known brands.
    Returns: {"match": bool, "brand": str|None}
    """
    try:
        if not url:
            return {"match": False}
        if url.endswith("/"):
            fav_url = url + "favicon.ico"
        else:
            fav_url = url + "/favicon.ico"
        resp = requests.get(fav_url, timeout=timeout)
        if resp.status_code != 200:
            return {"match": False}
        img = Image.open(BytesIO(resp.content))
        ph = imagehash.phash(img)
        for brand, refhex in KNOWN_BRAND_HASHES.items():
            if ph - imagehash.hex_to_hash(refhex) < 5:  # hamming distance threshold
                return {"match": True, "brand": brand}
        return {"match": False}
    except Exception:
        return {"match": False}
