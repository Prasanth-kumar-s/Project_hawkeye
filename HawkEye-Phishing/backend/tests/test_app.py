# tests/test_app.py
import json
import os
import pytest
from app import app

@pytest.fixture
def client():
    app.config["TESTING"] = True
    with app.test_client() as c:
        yield c

def test_healthz(client):
    r = client.get("/healthz")
    assert r.status_code == 200
    js = r.get_json()
    assert js.get("status") == "ok"

def test_analyze_url_missing(client):
    r = client.post("/analyze/url", json={})
    assert r.status_code == 400

def test_analyze_url_basic(client):
    r = client.post("/analyze/url", json={"url": "http://192.168.0.1/login"})
    assert r.status_code == 200
    js = r.get_json()
    assert "score" in js and "label" in js
