"""Lightweight error-based SQL injection probe.

This intentionally does NOT attempt blind/time-based or destructive payloads.
It submits a small set of classic error-triggering payloads to each form field
and looks for SQL error signatures or response-length anomalies in the reply.
"""
from __future__ import annotations

from typing import List

import requests

from scanner.crawler import DEFAULT_HEADERS, REQUEST_TIMEOUT, Page

PAYLOADS = ["'", "\"", "' OR '1'='1", "1' OR '1'='1' -- -"]

SQL_ERROR_SIGNATURES = [
    "you have an error in your sql syntax",
    "warning: mysql",
    "unclosed quotation mark",
    "quoted string not properly terminated",
    "sqlite3.operationalerror",
    "psql: error",
    "pg_query(): query failed",
    "ora-01756",
    "microsoft odbc",
    "syntax error at or near",
]


def _looks_vulnerable(baseline_text: str, test_text: str) -> str | None:
    lower = test_text.lower()
    for sig in SQL_ERROR_SIGNATURES:
        if sig in lower:
            return sig
    # crude anomaly heuristic: response ballooned or collapsed relative to baseline
    if baseline_text and abs(len(test_text) - len(baseline_text)) > max(500, len(baseline_text) * 2):
        return "response length anomaly vs baseline"
    return None


def run(pages: List[Page], session: requests.Session) -> List[dict]:
    findings = []
    session.headers.update(DEFAULT_HEADERS)

    for page in pages:
        for form in page.forms:
            if not form.fields:
                continue
            baseline_data = {f.name: "test" for f in form.fields}
            try:
                baseline_resp = _submit(session, form, baseline_data)
            except requests.RequestException:
                continue
            baseline_text = baseline_resp.text if baseline_resp is not None else ""

            for field_obj in form.fields:
                if field_obj.type in ("submit", "hidden", "checkbox", "radio"):
                    continue
                for payload in PAYLOADS:
                    data = {f.name: "test" for f in form.fields}
                    data[field_obj.name] = payload
                    try:
                        resp = _submit(session, form, data)
                    except requests.RequestException:
                        continue
                    if resp is None:
                        continue
                    reason = _looks_vulnerable(baseline_text, resp.text)
                    if reason:
                        findings.append({
                            "check": "sqli",
                            "severity": "critical",
                            "title": f"Possible SQL injection in field '{field_obj.name}'",
                            "description": (
                                f"Submitting payload {payload!r} to field '{field_obj.name}' on "
                                f"{form.action} triggered: {reason}."
                            ),
                            "url": form.action,
                            "evidence": f"payload={payload!r}, signal={reason}",
                            "remediation": "Use parameterized queries / prepared statements; never concatenate user input into SQL.",
                        })
                        break  # one confirmed hit per field is enough
    return findings


def _submit(session: requests.Session, form, data: dict) -> requests.Response | None:
    if form.method == "GET":
        return session.get(form.action, params=data, timeout=REQUEST_TIMEOUT)
    return session.post(form.action, data=data, timeout=REQUEST_TIMEOUT)
