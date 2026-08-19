"""Checks for missing/misconfigured security headers."""
from __future__ import annotations

from typing import List

from scanner.crawler import Page

REQUIRED_HEADERS = {
    "Content-Security-Policy": {
        "severity": "medium",
        "remediation": "Set a Content-Security-Policy header restricting script/style/frame sources.",
    },
    "X-Frame-Options": {
        "severity": "medium",
        "remediation": "Set X-Frame-Options: DENY or SAMEORIGIN to prevent clickjacking.",
    },
    "X-Content-Type-Options": {
        "severity": "low",
        "remediation": "Set X-Content-Type-Options: nosniff to stop MIME-type sniffing.",
    },
    "Strict-Transport-Security": {
        "severity": "high",
        "remediation": "Set Strict-Transport-Security with a long max-age once served over HTTPS.",
    },
    "Referrer-Policy": {
        "severity": "low",
        "remediation": "Set a Referrer-Policy (e.g. strict-origin-when-cross-origin) to limit referrer leakage.",
    },
}


def run(pages: List[Page]) -> List[dict]:
    findings = []
    seen_urls = set()
    for page in pages:
        if page.url in seen_urls:
            continue
        seen_urls.add(page.url)
        header_keys_lower = {k.lower() for k in page.headers}
        for header, meta in REQUIRED_HEADERS.items():
            if header.lower() not in header_keys_lower:
                findings.append({
                    "check": "headers",
                    "severity": meta["severity"],
                    "title": f"Missing {header} header",
                    "description": f"The response from {page.url} does not set the {header} header.",
                    "url": page.url,
                    "evidence": None,
                    "remediation": meta["remediation"],
                })
    return findings
