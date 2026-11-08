# coding: utf-8
"""Unit tests for the lexical feature extraction."""

import pandas as pd
import pytest

import featureExtraction as fe


def test_feature_names_and_dataframe_align():
    frame = fe.features_dataframe("https://example.com")
    assert list(frame.columns) == fe.FEATURE_NAMES
    assert len(frame) == 1
    # Every documented feature has a description.
    assert set(fe.FEATURE_NAMES) == set(fe.FEATURE_DESCRIPTIONS.keys())


def test_backward_compatible_alias():
    assert isinstance(fe.getAttributess("https://example.com"), pd.DataFrame)
    assert list(fe.getAttributess("https://example.com").columns) == fe.FEATURE_NAMES


def test_all_features_numeric():
    feats = fe.extract_features("http://a-b.example.co.uk/login?id=1&ok=2")
    assert feats  # non-empty
    for name, value in feats.items():
        assert isinstance(value, (int, float)), f"{name} is not numeric: {value!r}"


@pytest.mark.parametrize(
    "url, feature, expected",
    [
        ("https://example.com", "is_https", 1),
        ("http://example.com", "is_https", 0),
        ("http://user@example.com", "num_at", 1),
        ("http://192.168.0.1/login", "has_ip", 1),
        ("https://example.com", "has_ip", 0),
        ("http://my-bank.example.com", "has_prefix_suffix", 1),
        ("http://example.com", "has_prefix_suffix", 0),
        ("http://bit.ly/abcd", "has_shortener", 1),
        ("http://example.com/path", "has_shortener", 0),
        ("http://example.com/secure/login", "has_suspicious_word", 1),
        ("http://example.com/images/cat.png", "has_suspicious_word", 0),
        ("http://example.com/path//redirect", "has_redirection", 1),
        ("http://example.com/http://evil.com", "has_http_token", 1),
    ],
)
def test_known_feature_values(url, feature, expected):
    assert fe.extract_features(url)[feature] == expected


def test_subdomain_count_ignores_www():
    assert fe.extract_features("http://www.example.com")["num_subdomains"] == 0
    assert fe.extract_features("http://a.b.example.com")["num_subdomains"] == 2


def test_digit_ratio_bounds():
    ratio = fe.extract_features("http://123456.com/0000")["digit_ratio"]
    assert 0.0 <= ratio <= 1.0


def test_missing_scheme_is_handled():
    # Should not raise and should still produce a full vector.
    feats = fe.extract_features("example.com/login")
    assert feats["has_suspicious_word"] == 1
    assert len(feats) == len(fe.FEATURE_NAMES)


def test_empty_url_does_not_crash():
    feats = fe.extract_features("")
    assert feats["url_length"] == 0
    assert feats["digit_ratio"] == 0.0
