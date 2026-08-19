from __future__ import annotations

from fastapi.testclient import TestClient

from api.main import app

client = TestClient(app)


def test_health():
    resp = client.get("/health")
    assert resp.status_code == 200
    assert resp.json() == {"status": "ok"}


def test_scan_requires_authorization_confirmation():
    resp = client.post("/api/scan", json={"url": "http://example.com", "confirm_authorized": False})
    assert resp.status_code == 400


def test_scan_missing_scan_returns_404():
    resp = client.get("/api/scan/does-not-exist")
    assert resp.status_code == 404


def test_scan_accepts_valid_request(monkeypatch):
    # Don't actually crawl the network in this test — just check the
    # endpoint accepts the request and returns a pending/running scan.
    resp = client.post(
        "/api/scan",
        json={"url": "http://127.0.0.1:59999", "confirm_authorized": True, "max_depth": 1, "max_pages": 1},
    )
    assert resp.status_code == 202
    body = resp.json()
    assert body["target_url"] == "http://127.0.0.1:59999/"
    assert body["status"] in ("pending", "running")
