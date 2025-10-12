def compute_final_score(reasons: list, indicators: dict):
    """
    Weighted scoring:
      - Heuristics: up to 40 pts (8 per reason, capped at 40)
      - Feed hit (local/PhishTank): 60 pts
      - ML prob reserved: up to 20 pts (not used yet)
      - Extras (favicon/domain-age/expand) already embedded as reasons/indicators
    """
    # Heuristics weight
    score_h = min(len(reasons) * 8, 40)

    # Feed weight
    score_f = 60 if indicators.get("in_feed") else 0

    # ML reserved
    score_ml = int(float(indicators.get("ml_prob", 0.0)) * 20)

    total = score_h + score_f + score_ml
    total = max(0, min(100, int(total)))

    if total >= 70:
        label = "malicious"
    elif total >= 30:
        label = "suspicious"
    else:
        label = "benign"

    return {
        "score": total,
        "label": label,
        "confidence": round(total / 100.0, 2),
        "reasons": reasons
    }
