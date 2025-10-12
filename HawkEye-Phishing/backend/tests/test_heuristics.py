# tests/test_heuristics.py
from url_heuristics import basic_heuristics

def test_basic_heuristics_ip():
    res = basic_heuristics("http://192.168.1.10/login")
    assert any("ip_in_host" in r or "matches_pattern" in r for r in res)

def test_shortener_detect():
    res = basic_heuristics("https://bit.ly/abc123")
    assert "url_shortener" in res
