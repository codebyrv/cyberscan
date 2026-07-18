import re
import ipaddress
from urllib.parse import urlparse
import tldextract


SUSPICIOUS_KEYWORDS = [
    "login",
    "signin",
    "verify",
    "secure",
    "account",
    "update",
    "bank",
    "password",
    "confirm",
    "paypal",
    "ebay",
    "webscr",
    "admin"
]


SHORTENING_SERVICES = [
    "bit.ly",
    "tinyurl.com",
    "goo.gl",
    "t.co",
    "ow.ly",
    "buff.ly",
    "is.gd",
    "cutt.ly",
    "rebrand.ly"
]


def is_ip(domain):
    try:
        ipaddress.ip_address(domain)
        return True
    except ValueError:
        return False


def extract_features(url):
    parsed = urlparse(url)
    extracted = tldextract.extract(url)

    domain = extracted.domain
    suffix = extracted.suffix
    subdomain = extracted.subdomain

    hostname = parsed.hostname if parsed.hostname else ""

    features = {}

    # URL Features
    features["url"] = url
    features["url_length"] = len(url)
    features["scheme"] = parsed.scheme
    features["https"] = parsed.scheme == "https"

    # Domain
    features["domain"] = domain
    features["suffix"] = suffix
    features["subdomain"] = subdomain

    # Counts
    features["dot_count"] = url.count(".")
    features["hyphen_count"] = url.count("-")
    features["slash_count"] = url.count("/")
    features["question_count"] = url.count("?")
    features["equal_count"] = url.count("=")
    features["digit_count"] = sum(c.isdigit() for c in url)

    # Special Characters
    features["contains_at"] = "@" in url
    features["contains_double_slash"] = "//" in url[8:]
    features["contains_ip"] = is_ip(hostname)

    # Subdomains
    if subdomain:
        features["subdomain_count"] = len(subdomain.split("."))
    else:
        features["subdomain_count"] = 0

    # Suspicious Keywords
    found_keywords = []

    for word in SUSPICIOUS_KEYWORDS:
        if word.lower() in url.lower():
            found_keywords.append(word)

    features["suspicious_keywords"] = found_keywords
    features["keyword_count"] = len(found_keywords)

    # URL Shortener
    features["shortened_url"] = any(
        service in hostname for service in SHORTENING_SERVICES
    )

    return features