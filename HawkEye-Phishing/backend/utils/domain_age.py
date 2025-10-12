from datetime import datetime, timezone
import whois

def _as_datetime(dt):
    # python-whois may return list, naive dt, or None
    if isinstance(dt, list) and dt:
        dt = dt[0]
    if not dt:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt

def domain_age_days(domain: str):
    try:
        data = whois.whois(domain)
        creation = _as_datetime(data.creation_date)
        if not creation:
            return None
        return int((datetime.now(timezone.utc) - creation).days)
    except Exception:
        return None
