"""Checks Set-Cookie headers for missing Secure / HttpOnly / SameSite flags."""
from __future__ import annotations

from typing import List

import requests

from scanner.crawler import Page


def run(pages: List[Page], session: requests.Session) -> List[dict]:
    findings = []
    # requests' session cookie jar doesn't expose raw Set-Cookie flags well,
    # so we re-inspect raw headers captured per page.
    for page in pages:
        raw_cookie_headers = [v for k, v in page.headers.items() if k.lower() == "set-cookie"]
        if not raw_cookie_headers:
            continue
        for raw in raw_cookie_headers:
            cookie_name = raw.split("=")[0].strip()
            lower = raw.lower()
            missing = []
            if "secure" not in lower:
                missing.append("Secure")
            if "httponly" not in lower:
                missing.append("HttpOnly")
            if "samesite" not in lower:
                missing.append("SameSite")
            if missing:
                findings.append({
                    "check": "cookies",
                    "severity": "medium" if "HttpOnly" in missing else "low",
                    "title": f"Cookie '{cookie_name}' missing flags: {', '.join(missing)}",
                    "description": (
                        f"Cookie set on {page.url} is missing: {', '.join(missing)}. "
                        "This increases exposure to XSS-based theft and CSRF."
                    ),
                    "url": page.url,
                    "evidence": raw,
                    "remediation": "Set Secure, HttpOnly, and SameSite=Lax/Strict on session and auth cookies.",
                })
    return findings
