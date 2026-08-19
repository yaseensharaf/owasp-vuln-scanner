"""Probes for common sensitive files left exposed on the target.

Many apps (especially SPAs with client-side routing, like Angular/React
apps) return HTTP 200 with the same index page for *any* unmatched path
instead of a proper 404. A naive "status 200 = exposed" check produces
false positives across every path on those apps. To avoid that, this
check first requests a random, definitely-nonexistent path to establish
a baseline "not found" response, then only flags a sensitive path if its
response meaningfully differs from that baseline (different status code,
or a body that isn't just a copy of the baseline's catch-all page).
"""
from __future__ import annotations

import uuid
from typing import List, Optional
from urllib.parse import urljoin

import requests

from scanner.crawler import DEFAULT_HEADERS, REQUEST_TIMEOUT

SENSITIVE_PATHS = {
    ".git/config": "critical",
    ".git/HEAD": "critical",
    ".env": "critical",
    ".env.local": "critical",
    "wp-config.php.bak": "high",
    "config.php.bak": "high",
    ".DS_Store": "low",
    "backup.zip": "high",
    "backup.sql": "critical",
    "database.sql": "critical",
    ".htpasswd": "critical",
    "id_rsa": "critical",
    "web.config.bak": "high",
    "docker-compose.yml": "medium",
}


def _get_baseline(base_url: str, session: requests.Session) -> Optional[requests.Response]:
    """Requests a random nonexistent path to learn what this server's
    'not found' response looks like (status code + body length)."""
    probe_path = f"definitely-does-not-exist-{uuid.uuid4().hex}"
    target = urljoin(base_url, probe_path)
    try:
        return session.get(target, timeout=REQUEST_TIMEOUT, allow_redirects=False)
    except requests.RequestException:
        return None


def run(base_url: str, session: requests.Session | None = None) -> List[dict]:
    session = session or requests.Session()
    session.headers.update(DEFAULT_HEADERS)
    findings = []

    baseline = _get_baseline(base_url, session)
    baseline_status = baseline.status_code if baseline is not None else None
    baseline_body = baseline.content if baseline is not None else b""

    for path, severity in SENSITIVE_PATHS.items():
        target = urljoin(base_url, path)
        try:
            resp = session.get(target, timeout=REQUEST_TIMEOUT, allow_redirects=False)
        except requests.RequestException:
            continue

        if resp.status_code != 200 or len(resp.content) == 0:
            continue

        # If this server 200s everything (SPA catch-all, generic error
        # page, etc.), the baseline will look the same as this response.
        # Only flag when it genuinely differs from the "not found" case.
        if baseline_status == 200 and resp.content == baseline_body:
            continue

        findings.append({
            "check": "exposed_files",
            "severity": severity,
            "title": f"Potentially exposed sensitive file: /{path}",
            "description": f"{target} returned HTTP 200 with content distinct from the site's not-found response, suggesting this file may be publicly accessible.",
            "url": target,
            "evidence": f"HTTP {resp.status_code}, {len(resp.content)} bytes (baseline: HTTP {baseline_status}, {len(baseline_body)} bytes)",
            "remediation": f"Ensure /{path} is not served by the web server; block it at the server/proxy config level.",
        })

    return findings