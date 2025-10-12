# utils/domain_info.py
import whois
from datetime import datetime

def get_domain_age(domain: str) -> int:
    """
    Returns the age of a domain in days.
    Returns -1 if WHOIS data is missing or lookup fails.
    """
    try:
        data = whois.whois(domain)
        creation = data.creation_date

        # Some domains have multiple creation dates (list)
        if isinstance(creation, list):
            creation = creation[0]

        if not creation:
            return -1

        # Calculate age in days
        age_days = (datetime.now() - creation).days
        return age_days

    except Exception:
        # WHOIS lookup may fail for some domains or TLDs
        return -1
