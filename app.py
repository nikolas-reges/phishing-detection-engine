from __future__ import annotations

import ipaddress
import os
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlparse

from flask import Flask, jsonify, render_template, request


app = Flask(__name__)
app.config["JSON_SORT_KEYS"] = False


SUSPICIOUS_KEYWORDS = (
    "login",
    "verify",
    "secure",
    "account",
    "update",
    "banking",
    "confirm",
    "wallet",
    "password",
    "signin",
    "sign-in",
    "auth",
    "authenticate",
    "unlock",
    "validate",
    "billing",
    "payment",
    "invoice",
    "support",
    "reset",
    "recovery",
    "token",
    "credentials",
    "alert",
    "security",
    "limited",
    "urgent",
    "blocked",
    "suspended",
    "appeal",
    "session",
    "access",
    "gift",
    "prize",
    "free",
    "bonus",
    "pix",
    "cpf",
    "card",
    "credit",
    "debit",
)

SUSPICIOUS_TLDS = {
    ".xyz",
    ".tk",
    ".ml",
    ".ga",
    ".cf",
    ".gq",
    ".top",
    ".click",
    ".download",
}

COMMON_COUNTRY_SECOND_LEVELS = {
    "ac",
    "co",
    "com",
    "edu",
    "gov",
    "net",
    "org",
}

SCHEME_RE = re.compile(r"^[a-z][a-z0-9+.-]*://", re.IGNORECASE)
PERCENT_ENCODING_RE = re.compile(r"%[0-9a-fA-F]{2}")
BAD_PERCENT_RE = re.compile(r"%(?![0-9a-fA-F]{2})")


@dataclass(frozen=True)
class Finding:
    check_id: str
    title: str
    description: str
    severity: str
    weight: int
    evidence: str

    def to_alert(self) -> dict[str, Any]:
        return {
            "id": self.check_id,
            "title": self.title,
            "description": self.description,
            "severity": self.severity,
            "weight": self.weight,
            "evidence": self.evidence,
        }


def normalize_url(raw_url: str) -> tuple[str, bool]:
    stripped = raw_url.strip()
    if stripped.startswith("//"):
        return f"http:{stripped}", True
    if not SCHEME_RE.match(stripped):
        return f"http://{stripped}", True
    return stripped, False


def is_ip_address(hostname: str) -> bool:
    try:
        ipaddress.ip_address(hostname)
    except ValueError:
        return False
    return True


def domain_labels(hostname: str) -> list[str]:
    return [label for label in hostname.rstrip(".").split(".") if label]


def subdomain_depth(hostname: str) -> int:
    labels = domain_labels(hostname)
    if len(labels) <= 2:
        return 0

    root_label_count = 2
    if (
        len(labels[-1]) == 2
        and len(labels) >= 3
        and labels[-2] in COMMON_COUNTRY_SECOND_LEVELS
    ):
        root_label_count = 3

    return max(len(labels) - root_label_count, 0)


def has_extra_double_slash(raw_url: str) -> bool:
    without_first_scheme_separator = re.sub(
        r"^[a-z][a-z0-9+.-]*://",
        "",
        raw_url,
        count=1,
        flags=re.IGNORECASE,
    )
    if raw_url.startswith("//"):
        return True
    return "//" in without_first_scheme_separator


def classify_risk(score: int) -> str:
    if score >= 75:
        return "Critical"
    if score >= 50:
        return "Dangerous"
    if score >= 25:
        return "Suspicious"
    return "Safe"


def summarize(level: str, alert_count: int) -> str:
    if alert_count == 0:
        return "No configured phishing indicators were detected."
    if level == "Critical":
        return "Multiple high-risk phishing indicators were detected. Treat this URL as unsafe."
    if level == "Dangerous":
        return "Several phishing indicators were detected. Avoid visiting this URL unless it is verified through a trusted channel."
    if level == "Suspicious":
        return "Some phishing indicators were detected. Review the alerts before trusting this URL."
    return "Low-risk indicators were detected, but the URL still deserves normal caution."


def analyze_url(raw_url: str) -> dict[str, Any]:
    if not raw_url or not raw_url.strip():
        raise ValueError("A URL is required.")

    normalized_url, scheme_was_added = normalize_url(raw_url)
    parsed = urlparse(normalized_url)
    scheme = parsed.scheme.lower()
    hostname = (parsed.hostname or "").rstrip(".").lower()

    if not hostname:
        raise ValueError("The URL must include a valid host name or IP address.")

    decoded_for_keywords = normalized_url.lower()
    labels = domain_labels(hostname)
    alerts: list[Finding] = []
    host_is_ip = is_ip_address(hostname)

    keyword_matches = sorted(
        {keyword for keyword in SUSPICIOUS_KEYWORDS if keyword in decoded_for_keywords}
    )
    if keyword_matches:
        severity = "high" if len(keyword_matches) >= 3 else "medium"
        alerts.append(
            Finding(
                check_id="suspicious_keywords",
                title="Suspicious keyword detected",
                description="The URL contains terms commonly used in credential theft and account recovery lures.",
                severity=severity,
                weight=min(35, 10 + (len(keyword_matches) * 8)),
                evidence=", ".join(keyword_matches),
            )
        )

    # 2. Regra de Typosquatting Injetada
    if any(char.isdigit() for char in hostname):
        clean_host = (
            hostname.replace("0", "o")
            .replace("1", "i")
            .replace("3", "e")
            .replace("4", "a")
        )
        if any(m in clean_host for m in ["google", "caixa", "facebook", "netflix"]):
            alerts.append(
                Finding(
                    check_id="brand_typosquatting",
                    title="Brand Spoofing / Typosquatting detected",
                    description="The domain attempts to imitate a well-known brand using lookalike characters.",
                    severity="high",
                    weight=45,
                    evidence=hostname,
                )
            )

    if host_is_ip:
        alerts.append(
            Finding(
                check_id="ip_address_host",
                title="IP address used as host",
                description="Legitimate services normally use recognizable domains; raw IP hosts are common in phishing and malware delivery.",
                severity="high",
                weight=22,
                evidence=hostname,
            )
        )

    depth = subdomain_depth(hostname) if not host_is_ip else 0
    if depth > 3:
        alerts.append(
            Finding(
                check_id="excessive_subdomains",
                title="Excessive subdomain depth",
                description="Deeply nested subdomains can hide the true registered domain and imitate trusted brands.",
                severity="medium",
                weight=16,
                evidence=f"{depth} subdomain levels",
            )
        )

    stripped_url = raw_url.strip()
    if len(stripped_url) > 75:
        alerts.append(
            Finding(
                check_id="long_url",
                title="URL is unusually long",
                description="Long URLs can obscure the destination, tracking payloads, or deceptive redirects.",
                severity="low",
                weight=10,
                evidence=f"{len(stripped_url)} characters",
            )
        )

    tld = f".{labels[-1]}" if labels else ""
    if tld in SUSPICIOUS_TLDS:
        alerts.append(
            Finding(
                check_id="suspicious_tld",
                title="Suspicious top-level domain",
                description="This TLD is frequently abused in low-cost, short-lived phishing campaigns.",
                severity="high",
                weight=18,
                evidence=tld,
            )
        )

    if "@" in stripped_url:
        alerts.append(
            Finding(
                check_id="at_symbol",
                title="At sign present in URL",
                description="The @ symbol can disguise the real destination by placing trusted-looking text before the actual host.",
                severity="high",
                weight=16,
                evidence="@",
            )
        )

    if has_extra_double_slash(stripped_url):
        alerts.append(
            Finding(
                check_id="extra_double_slash",
                title="Extra double slash detected",
                description="Unexpected double slashes after the scheme can indicate redirect tricks or URL parsing deception.",
                severity="medium",
                weight=10,
                evidence="//",
            )
        )

    encoded_tokens = PERCENT_ENCODING_RE.findall(stripped_url)
    has_encoded_space = any(token.lower() == "%20" for token in encoded_tokens)
    encoded_non_space = sorted(
        {token.upper() for token in encoded_tokens if token.lower() != "%20"}
    )
    malformed_percent_count = len(BAD_PERCENT_RE.findall(stripped_url))

    if has_encoded_space:
        alerts.append(
            Finding(
                check_id="encoded_space",
                title="Encoded space present",
                description="Encoded spaces are often used to make malicious links harder to read or validate.",
                severity="medium",
                weight=8,
                evidence="%20",
            )
        )

    if encoded_non_space or malformed_percent_count:
        evidence_parts = []
        if encoded_non_space:
            evidence_parts.append(", ".join(encoded_non_space[:8]))
        if malformed_percent_count:
            evidence_parts.append(f"{malformed_percent_count} malformed percent marker(s)")

        alerts.append(
            Finding(
                check_id="encoded_characters",
                title="Encoded or obfuscated characters",
                description="Percent-encoded characters can hide the readable intent of a URL or bypass simple filters.",
                severity="medium",
                weight=9,
                evidence="; ".join(evidence_parts),
            )
        )

    hyphen_count = hostname.count("-")
    if hyphen_count > 2:
        alerts.append(
            Finding(
                check_id="hyphenated_domain",
                title="Heavily hyphenated domain",
                description="Domains with many hyphens are often generated to mimic brands or create believable lookalikes.",
                severity="medium",
                weight=12,
                evidence=f"{hyphen_count} hyphens in host",
            )
        )

    if scheme != "https":
        if scheme_was_added:
            title = "HTTPS scheme missing"
            evidence = "No scheme supplied; analyzed as HTTP"
        elif scheme == "http":
            title = "HTTP used instead of HTTPS"
            evidence = "http://"
        else:
            title = "Non-HTTPS scheme used"
            evidence = f"{scheme}://"

        alerts.append(
            Finding(
                check_id="not_https",
                title=title,
                description="Credentials and session data should only be exchanged over HTTPS-protected connections.",
                severity="medium",
                weight=12,
                evidence=evidence,
            )
        )

    score = min(sum(alert.weight for alert in alerts), 100)
    level = classify_risk(score)

    return {
        "input_url": stripped_url,
        "normalized_url": normalized_url,
        "scheme": scheme,
        "host": hostname,
        "risk_score": score,
        "risk_level": level,
        "summary": summarize(level, len(alerts)),
        "alerts": [alert.to_alert() for alert in alerts],
        "metrics": {
            "url_length": len(stripped_url),
            "subdomain_depth": depth,
            "hyphen_count": hyphen_count,
            "keyword_matches": keyword_matches,
            "host_is_ip": host_is_ip,
            "tld": tld,
        },
        "checked_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
    }


@app.after_request
def set_security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "style-src 'self' 'unsafe-inline'; "
        "script-src 'self' 'unsafe-inline'; "
        "img-src 'self' data:; "
        "connect-src 'self'; "
        "base-uri 'self'; "
        "form-action 'self'"
    )
    return response


@app.get("/")
def index():
    return render_template("index.html")


@app.post("/api/analyze")
def api_analyze():
    payload = request.get_json(silent=True) or {}
    candidate_url = str(payload.get("url", "")).strip()

    try:
        report = analyze_url(candidate_url)
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400

    return jsonify(report)


@app.get("/health")
def health():
    return jsonify({"status": "ok"})


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5003, debug=False)