"""Orchestrates a full scan: crawl -> run all checks -> collect findings.

Supports an optional `on_finding` callback so callers (e.g. the API's
WebSocket handler) can stream results as they're discovered instead of
waiting for the whole scan to finish.
"""
from __future__ import annotations

import logging
import uuid
from typing import Callable, List, Optional

import requests

from scanner import crawler
from scanner.checks import cookies, csrf, exposed_files, headers, sqli, xss

logger = logging.getLogger(__name__)

FindingCallback = Callable[[dict], None]


def run_scan(
    target_url: str,
    max_depth: int = 2,
    max_pages: int = 50,
    on_finding: Optional[FindingCallback] = None,
) -> dict:
    """Runs the full scan pipeline and returns a dict with pages_crawled + findings.

    Each finding dict matches the shape expected by api.models.Finding
    (minus scan-level fields like scan_id, which the caller attaches).
    """
    session = requests.Session()
    findings: List[dict] = []

    def emit(new_findings: List[dict]) -> None:
        for f in new_findings:
            f["id"] = str(uuid.uuid4())
            findings.append(f)
            if on_finding:
                on_finding(f)

    logger.info("Crawling %s (depth=%s, max_pages=%s)", target_url, max_depth, max_pages)
    pages = crawler.crawl(target_url, max_depth=max_depth, max_pages=max_pages, session=session)
    logger.info("Crawled %d pages", len(pages))

    # Fast, non-invasive checks first
    emit(headers.run(pages))
    emit(exposed_files.run(target_url, session=session))
    emit(cookies.run(pages, session=session))
    emit(csrf.run(pages))

    # Active/invasive checks last
    emit(sqli.run(pages, session=session))
    emit(xss.run(pages, session=session))

    return {
        "pages_crawled": len(pages),
        "findings": findings,
    }
