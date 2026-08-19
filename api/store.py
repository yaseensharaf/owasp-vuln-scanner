"""In-memory scan job store.

Fine for a portfolio project / single-instance deployment. Swap for
Redis or a database if this ever needs to run across multiple workers.
"""
from __future__ import annotations

import threading
from typing import Dict, Optional

from api.models import ScanResult

_lock = threading.Lock()
_scans: Dict[str, ScanResult] = {}


def save(scan: ScanResult) -> None:
    with _lock:
        _scans[scan.scan_id] = scan


def get(scan_id: str) -> Optional[ScanResult]:
    with _lock:
        return _scans.get(scan_id)


def all_scans() -> Dict[str, ScanResult]:
    with _lock:
        return dict(_scans)
