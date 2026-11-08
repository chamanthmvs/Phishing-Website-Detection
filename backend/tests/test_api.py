# coding: utf-8
"""Integration tests for the FastAPI endpoints."""

from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)


def test_health():
    r = client.get("/api/health")
    assert r.status_code == 200
    body = r.json()
    assert body["status"] == "ok"
    assert body["models_loaded"] >= 1


def test_list_models():
    r = client.get("/api/models")
    assert r.status_code == 200
    body = r.json()
    assert body["models"], "expected at least one model"
    assert any(m["is_default"] for m in body["models"])
    for m in body["models"]:
        assert "metrics" in m
        assert m["metrics"]["test_accuracy"] is not None


def test_scan_phishing_url():
    r = client.post("/api/scan", json={"url": "http://paypal.secure-login.tk/webscr?cmd=verify"})
    assert r.status_code == 200
    body = r.json()
    assert body["is_phishing"] is True
    assert body["label"] == "Phishing"
    assert 0.0 <= body["confidence"] <= 1.0
    assert len(body["features"]) >= 10


def test_scan_legit_url():
    r = client.post("/api/scan", json={"url": "https://github.com/chamanthmvs/Phishing-Website-Detection"})
    assert r.status_code == 200
    assert r.json()["is_phishing"] is False


def test_scan_with_explicit_model():
    r = client.post("/api/scan", json={"url": "https://www.google.com", "model": "logistic_regression"})
    assert r.status_code == 200
    assert r.json()["model"] == "logistic_regression"


def test_scan_unknown_model_404():
    r = client.post("/api/scan", json={"url": "https://www.google.com", "model": "nope"})
    assert r.status_code == 404


def test_scan_empty_url_422():
    r = client.post("/api/scan", json={"url": ""})
    assert r.status_code == 422
