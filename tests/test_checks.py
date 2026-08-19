"""Unit tests for individual checks. Uses a local Flask app as a controlled
target instead of hitting the real internet, so CI is fast and deterministic.
"""
from __future__ import annotations

import threading
import time

import pytest
import requests
from flask import Flask, request as flask_request

from scanner import crawler
from scanner.checks import cookies, csrf, exposed_files, headers, sqli, xss


@pytest.fixture(scope="module")
def vulnerable_app_url():
    """Spins up a tiny deliberately-vulnerable Flask app in a thread."""
    app = Flask(__name__)

    @app.route("/")
    def index():
        # No security headers, no CSRF token, missing cookie flags
        resp = app.make_response(
            """
            <html><body>
              <form method="POST" action="/search">
                <input name="q" type="text">
                <input type="submit">
              </form>
            </body></html>
            """
        )
        resp.headers["Set-Cookie"] = "session=abc123"
        return resp

    @app.route("/search", methods=["POST"])
    def search():
        q = flask_request.form.get("q", "")
        # Deliberately leak a SQL error signature for classic SQLi probe
        # payloads only (quote-leading or "OR '1'='1'" patterns) so this
        # doesn't collide with the XSS payload, which also contains a quote.
        if q.startswith("'") or q.startswith('"') or "or '1'='1'" in q.lower():
            return "Error: you have an error in your sql syntax near '%s'" % q, 500
        # Deliberately reflect everything else unescaped -> XSS
        return f"<html><body>Results for: {q}</body></html>"

    @app.route("/.env")
    def exposed_env():
        return "SECRET_KEY=supersecret\n", 200

    server_thread = threading.Thread(
        target=lambda: app.run(port=5099, use_reloader=False), daemon=True
    )
    server_thread.start()
    time.sleep(0.5)
    yield "http://127.0.0.1:5099"


def test_headers_check_flags_missing_headers(vulnerable_app_url):
    pages = crawler.crawl(vulnerable_app_url, max_depth=1, max_pages=5)
    findings = headers.run(pages)
    assert any(f["check"] == "headers" for f in findings)


def test_exposed_files_check_finds_env(vulnerable_app_url):
    findings = exposed_files.run(vulnerable_app_url)
    assert any(".env" in f["url"] for f in findings)


def test_cookies_check_flags_missing_flags(vulnerable_app_url):
    pages = crawler.crawl(vulnerable_app_url, max_depth=1, max_pages=5)
    findings = cookies.run(pages, requests.Session())
    assert any(f["check"] == "cookies" for f in findings)


def test_csrf_check_flags_form_without_token(vulnerable_app_url):
    pages = crawler.crawl(vulnerable_app_url, max_depth=1, max_pages=5)
    findings = csrf.run(pages)
    assert any(f["check"] == "csrf" for f in findings)


def test_sqli_check_detects_error_signature(vulnerable_app_url):
    pages = crawler.crawl(vulnerable_app_url, max_depth=1, max_pages=5)
    findings = sqli.run(pages, requests.Session())
    assert any(f["check"] == "sqli" for f in findings)


def test_xss_check_detects_reflected_payload(vulnerable_app_url):
    pages = crawler.crawl(vulnerable_app_url, max_depth=1, max_pages=5)
    findings = xss.run(pages, requests.Session())
    assert any(f["check"] == "xss" for f in findings)
