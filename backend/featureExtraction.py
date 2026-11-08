# coding: utf-8
"""URL feature extraction for the Phishing Website Detection model.

All features are *lexical*: they are computed purely from the URL string with
no network access. This makes feature extraction fast, deterministic, fully
reproducible, and testable, and it means the app behaves identically on a
laptop and on a locked-down cloud host (where outbound WHOIS/DNS is often
blocked).

Public API
----------
- ``FEATURE_NAMES``        : ordered list of feature column names.
- ``FEATURE_DESCRIPTIONS`` : human-readable explanation for each feature.
- ``extract_features(url)``: ``dict`` of feature name -> numeric value.
- ``features_dataframe(url)`` / ``getAttributess(url)``: single-row DataFrame
  whose column order matches ``FEATURE_NAMES`` (kept for backward
  compatibility with the original project).
"""

from __future__ import annotations

import re
from collections import OrderedDict
from urllib.parse import urlparse

import pandas as pd

# ---------------------------------------------------------------------------
# Reference data
# ---------------------------------------------------------------------------

# Common URL-shortening services. A shortened link hides the true destination,
# a frequent phishing tactic.
SHORTENING_SERVICES = (
    r"bit\.ly|goo\.gl|shorte\.st|go2l\.ink|x\.co|ow\.ly|t\.co|tinyurl|tr\.im|"
    r"is\.gd|cli\.gs|yfrog\.com|migre\.me|ff\.im|tiny\.cc|url4\.eu|twit\.ac|"
    r"su\.pr|twurl\.nl|snipurl\.com|short\.to|budurl\.com|ping\.fm|post\.ly|"
    r"just\.as|bkite\.com|snipr\.com|fic\.kr|loopt\.us|doiop\.com|short\.ie|"
    r"kl\.am|wp\.me|rubyurl\.com|om\.ly|to\.ly|bit\.do|lnkd\.in|db\.tt|qr\.ae|"
    r"adf\.ly|cur\.lv|bitly\.com|ity\.im|q\.gs|po\.st|bc\.vc|twitthis\.com|"
    r"u\.to|j\.mp|buzurl\.com|cutt\.us|u\.bb|yourls\.org|prettylinkpro\.com|"
    r"scrnch\.me|filoops\.info|vzturl\.com|qr\.net|1url\.com|tweez\.me|v\.gd|"
    r"link\.zip\.net|rb\.gy|cutt\.ly|rebrand\.ly|shorturl\.at"
)

# Words frequently embedded in phishing URLs to imitate trusted actions/brands.
SUSPICIOUS_WORDS = (
    "login",
    "signin",
    "verify",
    "verification",
    "account",
    "update",
    "secure",
    "security",
    "banking",
    "bank",
    "confirm",
    "password",
    "credential",
    "ebayisapi",
    "webscr",
    "paypal",
    "wp-admin",
    "submit",
    "suspend",
    "unlock",
    "recover",
    "billing",
    "invoice",
    "wallet",
    "authenticate",
)

# IPv4 / hex-IPv4 address appearing where a hostname should be.
_IP_PATTERN = re.compile(
    r"(?:(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d?\d)"
    r"|(?:0x[0-9a-fA-F]{1,2}\.){3}0x[0-9a-fA-F]{1,2}"
)
_SHORTENER_RE = re.compile(SHORTENING_SERVICES, re.IGNORECASE)
_SUSPICIOUS_RE = re.compile("|".join(re.escape(w) for w in SUSPICIOUS_WORDS), re.IGNORECASE)


# ---------------------------------------------------------------------------
# Feature metadata (order matters: this is the model's input layout)
# ---------------------------------------------------------------------------

FEATURE_DESCRIPTIONS = OrderedDict(
    [
        ("url_length", "Total number of characters in the URL."),
        ("hostname_length", "Number of characters in the hostname."),
        ("path_length", "Number of characters in the URL path."),
        ("num_dots", "Count of '.' characters (more dots often means more subdomains)."),
        ("num_hyphens", "Count of '-' characters in the URL."),
        ("num_at", "Count of '@' characters (an '@' can hide the real destination)."),
        ("num_question_marks", "Count of '?' characters (query parameters)."),
        ("num_ampersand", "Count of '&' characters (query parameters)."),
        ("num_equals", "Count of '=' characters (query parameters)."),
        ("num_percent", "Count of '%' characters (percent-encoding can obscure content)."),
        ("num_digits", "Count of digit characters in the URL."),
        ("num_subdomains", "Number of subdomain labels in the hostname."),
        ("has_ip", "1 if the host is a raw IP address instead of a domain name."),
        ("is_https", "1 if the URL uses the https scheme."),
        ("has_http_token", "1 if 'http' appears again after the scheme (a spoofing trick)."),
        ("has_prefix_suffix", "1 if the domain contains a '-' (brand look-alike trick)."),
        ("has_shortener", "1 if a URL-shortening service is used."),
        ("has_redirection", "1 if '//' appears inside the path (open-redirect pattern)."),
        ("has_suspicious_word", "1 if the URL contains a known phishing keyword."),
        ("digit_ratio", "Fraction of the URL made up of digits."),
    ]
)

FEATURE_NAMES = list(FEATURE_DESCRIPTIONS.keys())


# ---------------------------------------------------------------------------
# Core extraction
# ---------------------------------------------------------------------------

def _normalize(url: str) -> str:
    """Return a trimmed URL that has a scheme so urlparse behaves consistently."""
    url = (url or "").strip()
    if not url:
        return ""
    if "://" not in url:
        url = "http://" + url
    return url


def extract_features(url: str) -> "OrderedDict[str, float]":
    """Extract the lexical feature vector for ``url`` as an ordered dict."""
    raw = (url or "").strip()
    normalized = _normalize(raw)
    parsed = urlparse(normalized)

    hostname = (parsed.hostname or "").lower()
    path = parsed.path or ""
    scheme = (parsed.scheme or "").lower()

    url_length = len(raw)
    # The part of the URL after the scheme, used to spot a repeated "http" token.
    after_scheme = normalized.split("://", 1)[1] if "://" in normalized else normalized

    # Subdomain count: labels in the hostname beyond the registrable domain + TLD.
    if hostname and not _IP_PATTERN.fullmatch(hostname):
        labels = [part for part in hostname.split(".") if part]
        if labels and labels[0] == "www":
            labels = labels[1:]
        num_subdomains = max(len(labels) - 2, 0)
    else:
        num_subdomains = 0

    digit_count = sum(ch.isdigit() for ch in raw)

    features = OrderedDict()
    features["url_length"] = url_length
    features["hostname_length"] = len(hostname)
    features["path_length"] = len(path)
    features["num_dots"] = raw.count(".")
    features["num_hyphens"] = raw.count("-")
    features["num_at"] = raw.count("@")
    features["num_question_marks"] = raw.count("?")
    features["num_ampersand"] = raw.count("&")
    features["num_equals"] = raw.count("=")
    features["num_percent"] = raw.count("%")
    features["num_digits"] = digit_count
    features["num_subdomains"] = num_subdomains
    features["has_ip"] = int(bool(_IP_PATTERN.search(hostname or raw)))
    features["is_https"] = int(scheme == "https")
    features["has_http_token"] = int(bool(re.search(r"https?", after_scheme, re.IGNORECASE)))
    features["has_prefix_suffix"] = int("-" in hostname)
    features["has_shortener"] = int(bool(_SHORTENER_RE.search(raw)))
    features["has_redirection"] = int("//" in path)
    features["has_suspicious_word"] = int(bool(_SUSPICIOUS_RE.search(raw)))
    features["digit_ratio"] = round(digit_count / url_length, 4) if url_length else 0.0

    return features


def features_dataframe(url: str) -> pd.DataFrame:
    """Return a single-row DataFrame with columns in ``FEATURE_NAMES`` order."""
    features = extract_features(url)
    return pd.DataFrame([features], columns=FEATURE_NAMES)


# Backward-compatible alias used by the original project / app.
def getAttributess(url: str) -> pd.DataFrame:  # noqa: N802 (kept for compatibility)
    return features_dataframe(url)
