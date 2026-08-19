"""Pydantic schemas shared across the API."""
from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import List, Optional

from pydantic import BaseModel, Field, HttpUrl


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class ScanStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"


class ScanRequest(BaseModel):
    url: HttpUrl
    confirm_authorized: bool = Field(
        ...,
        description=(
            "Must be true. You must own this target or have explicit written "
            "authorization to scan it. Scanning systems without authorization "
            "may be illegal in your jurisdiction."
        ),
    )
    max_depth: int = Field(2, ge=1, le=5, description="Crawl depth limit")
    max_pages: int = Field(50, ge=1, le=500, description="Max pages to crawl")


class Finding(BaseModel):
    id: str
    check: str  # e.g. "sqli", "xss", "headers", "exposed_files", "csrf", "cookies"
    severity: Severity
    title: str
    description: str
    url: str
    evidence: Optional[str] = None
    remediation: str


class ScanResult(BaseModel):
    scan_id: str
    target_url: str
    status: ScanStatus
    started_at: datetime
    finished_at: Optional[datetime] = None
    pages_crawled: int = 0
    findings: List[Finding] = []

    @property
    def summary(self) -> dict:
        counts = {s.value: 0 for s in Severity}
        for f in self.findings:
            counts[f.severity.value] += 1
        return counts
