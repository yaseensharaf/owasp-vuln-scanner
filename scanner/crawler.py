"""Same-origin crawler: discovers pages, links, and forms to feed the checks."""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import List, Set
from urllib.parse import urljoin, urlparse

import requests
from bs4 import BeautifulSoup

logger = logging.getLogger(__name__)

DEFAULT_HEADERS = {
    "User-Agent": "owasp-vuln-scanner/1.0 (authorized-scan-only)"
}
REQUEST_TIMEOUT = 8


@dataclass
class FormField:
    name: str
    type: str = "text"


@dataclass
class Form:
    action: str
    method: str
    fields: List[FormField] = field(default_factory=list)
    has_csrf_token: bool = False


@dataclass
class Page:
    url: str
    status_code: int
    headers: dict
    cookies: dict
    forms: List[Form] = field(default_factory=list)
    html: str = ""


CSRF_FIELD_HINTS = {"csrf", "_token", "authenticity_token", "csrfmiddlewaretoken", "xsrf"}


def _same_origin(base: str, candidate: str) -> bool:
    b, c = urlparse(base), urlparse(candidate)
    return b.scheme == c.scheme and b.netloc == c.netloc


def _extract_forms(base_url: str, soup: BeautifulSoup) -> List[Form]:
    forms = []
    for tag in soup.find_all("form"):
        action = urljoin(base_url, tag.get("action") or base_url)
        method = (tag.get("method") or "GET").upper()
        fields = []
        has_csrf = False
        for inp in tag.find_all(["input", "textarea", "select"]):
            name = inp.get("name")
            if not name:
                continue
            ftype = inp.get("type", "text")
            fields.append(FormField(name=name, type=ftype))
            if any(hint in name.lower() for hint in CSRF_FIELD_HINTS):
                has_csrf = True
        forms.append(Form(action=action, method=method, fields=fields, has_csrf_token=has_csrf))
    return forms


def crawl(base_url: str, max_depth: int = 2, max_pages: int = 50,
          session: requests.Session | None = None) -> List[Page]:
    """Breadth-first crawl of same-origin pages, up to max_depth / max_pages."""
    session = session or requests.Session()
    session.headers.update(DEFAULT_HEADERS)

    visited: Set[str] = set()
    queue: List[tuple[str, int]] = [(base_url, 0)]
    pages: List[Page] = []

    while queue and len(pages) < max_pages:
        url, depth = queue.pop(0)
        if url in visited or depth > max_depth:
            continue
        visited.add(url)

        try:
            resp = session.get(url, timeout=REQUEST_TIMEOUT, allow_redirects=True)
        except requests.RequestException as exc:
            logger.warning("Failed to fetch %s: %s", url, exc)
            continue

        content_type = resp.headers.get("Content-Type", "")
        if "text/html" not in content_type:
            pages.append(Page(url=url, status_code=resp.status_code,
                               headers=dict(resp.headers),
                               cookies=session.cookies.get_dict()))
            continue

        soup = BeautifulSoup(resp.text, "html.parser")
        forms = _extract_forms(url, soup)
        pages.append(Page(url=url, status_code=resp.status_code,
                           headers=dict(resp.headers),
                           cookies=session.cookies.get_dict(),
                           forms=forms, html=resp.text))

        if depth < max_depth:
            for a in soup.find_all("a", href=True):
                link = urljoin(url, a["href"]).split("#")[0]
                if _same_origin(base_url, link) and link not in visited:
                    queue.append((link, depth + 1))

    return pages
