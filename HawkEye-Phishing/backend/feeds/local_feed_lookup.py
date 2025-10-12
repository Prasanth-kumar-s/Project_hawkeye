import os
import sqlite3
from datetime import date

DB_PATH = os.path.join(os.path.dirname(__file__), "phishtank_local.db")

def ensure_feed_db(force_recreate: bool = False):
    """
    Create the SQLite DB & table if missing.
    If force_recreate=True, drops and recreates the table (dev convenience).
    """
    con = sqlite3.connect(DB_PATH)
    cur = con.cursor()
    if force_recreate:
        try:
            cur.execute("DROP TABLE IF EXISTS bad_domains")
        except Exception:
            pass
    cur.execute("""
        CREATE TABLE IF NOT EXISTS bad_domains (
            domain TEXT PRIMARY KEY,
            source TEXT,
            date_added TEXT
        )
    """)
    con.commit()
    con.close()

def check_domain_in_local_feed(domain: str) -> bool:
    """Return True if domain is present in local feed DB."""
    try:
        con = sqlite3.connect(DB_PATH)
        cur = con.cursor()
        cur.execute("SELECT 1 FROM bad_domains WHERE domain = ?", (domain,))
        hit = cur.fetchone() is not None
        con.close()
        return hit
    except Exception:
        return False

def add_bad_domain(domain: str, source: str = "manual"):
    """Dev helper: manually insert a domain for testing."""
    con = sqlite3.connect(DB_PATH)
    cur = con.cursor()
    cur.execute(
        "INSERT OR IGNORE INTO bad_domains(domain, source, date_added) VALUES (?, ?, ?)",
        (domain, source, date.today().isoformat()),
    )
    con.commit()
    con.close()
