"""Flags state-changing forms (POST/PUT/DELETE) with no CSRF token field."""
from __future__ import annotations

from typing import List

from scanner.crawler import Page

STATE_CHANGING_METHODS = {"POST", "PUT", "DELETE", "PATCH"}


def run(pages: List[Page]) -> List[dict]:
    findings = []
    for page in pages:
        for form in page.forms:
            if form.method not in STATE_CHANGING_METHODS:
                continue
            if not form.has_csrf_token:
                findings.append({
                    "check": "csrf",
                    "severity": "medium",
                    "title": "Form missing CSRF token",
                    "description": (
                        f"A {form.method} form on {page.url} (action: {form.action}) "
                        "has no recognizable CSRF token field."
                    ),
                    "url": page.url,
                    "evidence": f"action={form.action}, fields={[f.name for f in form.fields]}",
                    "remediation": "Add a per-session CSRF token to all state-changing forms and validate it server-side.",
                })
    return findings
