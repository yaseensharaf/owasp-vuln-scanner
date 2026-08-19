"""Reflected XSS probe: injects a unique marker payload and checks if it
comes back unescaped in the HTML response."""
from __future__ import annotations

import uuid
from typing import List

import requests

from scanner.crawler import DEFAULT_HEADERS, REQUEST_TIMEOUT, Page


def _payload(marker: str) -> str:
    return f"<script>/*{marker}*/alert('{marker}')</script>"


def run(pages: List[Page], session: requests.Session) -> List[dict]:
    findings = []
    session.headers.update(DEFAULT_HEADERS)

    for page in pages:
        for form in page.forms:
            if not form.fields:
                continue
            for field_obj in form.fields:
                if field_obj.type in ("submit", "hidden", "checkbox", "radio"):
                    continue
                marker = f"xsstest{uuid.uuid4().hex[:8]}"
                payload = _payload(marker)
                data = {f.name: "test" for f in form.fields}
                data[field_obj.name] = payload

                try:
                    if form.method == "GET":
                        resp = session.get(form.action, params=data, timeout=REQUEST_TIMEOUT)
                    else:
                        resp = session.post(form.action, data=data, timeout=REQUEST_TIMEOUT)
                except requests.RequestException:
                    continue

                if payload in resp.text:
                    findings.append({
                        "check": "xss",
                        "severity": "high",
                        "title": f"Reflected XSS in field '{field_obj.name}'",
                        "description": (
                            f"A script payload submitted to field '{field_obj.name}' on "
                            f"{form.action} was reflected unescaped in the response."
                        ),
                        "url": form.action,
                        "evidence": f"marker={marker}",
                        "remediation": "HTML-escape all user input before rendering; set a strict Content-Security-Policy as defense in depth.",
                    })
    return findings
