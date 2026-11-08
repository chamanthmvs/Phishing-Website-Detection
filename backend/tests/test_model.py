# coding: utf-8
"""Tests that the saved models load and behave sensibly via the registry."""

import json
from pathlib import Path

import pytest

import featureExtraction as fe
from app.registry import Registry

ROOT = Path(__file__).resolve().parents[1]
MODELS_DIR = ROOT / "models"
METADATA_PATH = MODELS_DIR / "models_metadata.json"


@pytest.fixture(scope="module")
def registry():
    return Registry()


def test_metadata_exists_and_matches_feature_layout():
    assert METADATA_PATH.exists(), "Run `python train.py` to create the models."
    meta = json.loads(METADATA_PATH.read_text(encoding="utf-8"))
    assert meta["feature_names"] == fe.FEATURE_NAMES


def test_all_models_loaded(registry):
    assert len(registry.available) >= 1
    assert registry.default_model in registry.available


def test_every_model_predicts_binary(registry):
    for name in registry.available:
        result = registry.predict("http://paypal.secure-login.tk/verify", name)
        assert result["is_phishing"] in (True, False)
        p = result["probabilities"]
        assert abs(p["legitimate"] + p["phishing"] - 1.0) < 1e-6
        assert len(result["features"]) == len(fe.FEATURE_NAMES)


def test_unknown_model_raises(registry):
    from app.registry import ModelNotFoundError

    with pytest.raises(ModelNotFoundError):
        registry.predict("http://example.com", "does_not_exist")


KNOWN_LEGIT = [
    "https://www.google.com",
    "https://github.com/chamanthmvs/Phishing-Website-Detection",
    "https://en.wikipedia.org/wiki/Phishing",
    "https://stackoverflow.com/questions/12345/how-to-parse-a-url-in-python",
    "https://www.amazon.com/dp/B08N5WRWNW",
    "https://www.youtube.com/watch?v=dQw4w9WgXcQ",
]
KNOWN_PHISH = [
    "http://paypal.secure-login.tk/webscr?cmd=verify-account",
    "http://bit.ly/3xYzAbc",
    "http://secure-update-account.confirm-identity.verify-paypal.com.tk/login",
    "http://login-bankofamerica.com.session-verify.ru/update",
]


def test_default_model_does_not_flag_known_legit(registry):
    wrong = [u for u in KNOWN_LEGIT if registry.predict(u)["is_phishing"]]
    assert not wrong, f"Legit URLs flagged as phishing: {wrong}"


def test_default_model_detects_known_phishing(registry):
    missed = [u for u in KNOWN_PHISH if not registry.predict(u)["is_phishing"]]
    assert not missed, f"Phishing URLs missed: {missed}"
