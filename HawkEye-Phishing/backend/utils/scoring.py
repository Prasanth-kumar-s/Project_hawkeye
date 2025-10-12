# utils/scoring.py
from typing import List, Dict

def compute_final_score(reasons: List[str], phish_info: Dict) -> Dict:
    """
    Very small scoring function that combines heuristic flags and threat feed.
    Returns dict with numeric score 0..100, label, confidence, and reasons.
    """
    base = 0
    details = list(reasons)  # copy

    # heuristics weight
    if details:
        # heuristics contribute up to 40 points (spread by count)
        base += min(len(details) * 8, 40)

    # threat feed weight (PhishTank)
    if phish_info.get("in_database"):
        base += 60

    # clamp
    score = max(0, min(100, base))

    # map to label
    if score >= 70:
        label = "malicious"
    elif score >= 30:
        label = "suspicious"
    else:
        label = "benign"

    # confidence heuristic: proportion of weighted evidence
    confidence = round(score / 100.0, 2)

    return {
        "score": int(score),
        "label": label,
        "confidence": confidence,
        "reasons": details
    }
