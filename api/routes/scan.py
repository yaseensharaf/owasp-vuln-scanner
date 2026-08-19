from __future__ import annotations

import asyncio
import logging
import uuid
from datetime import datetime, timezone

from fastapi import APIRouter, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.responses import Response

from api import store
from api.models import Finding, ScanRequest, ScanResult, ScanStatus
from scanner.engine import run_scan
from scanner.report import build_pdf

logger = logging.getLogger(__name__)
router = APIRouter()

# scan_id -> list of asyncio.Queue, so multiple clients can watch one scan
_subscribers: dict[str, list[asyncio.Queue]] = {}


def _subscribe(scan_id: str) -> asyncio.Queue:
    q: asyncio.Queue = asyncio.Queue()
    _subscribers.setdefault(scan_id, []).append(q)
    return q


def _unsubscribe(scan_id: str, q: asyncio.Queue) -> None:
    subs = _subscribers.get(scan_id, [])
    if q in subs:
        subs.remove(q)


def _publish(scan_id: str, message: dict) -> None:
    for q in _subscribers.get(scan_id, []):
        q.put_nowait(message)


@router.post("/scan", response_model=ScanResult, status_code=202)
async def start_scan(req: ScanRequest):
    if not req.confirm_authorized:
        raise HTTPException(
            status_code=400,
            detail="You must confirm you own or are explicitly authorized to scan this target.",
        )

    scan_id = str(uuid.uuid4())
    result = ScanResult(
        scan_id=scan_id,
        target_url=str(req.url),
        status=ScanStatus.PENDING,
        started_at=datetime.now(timezone.utc),
    )
    store.save(result)

    loop = asyncio.get_event_loop()
    asyncio.create_task(_run_scan_task(loop, scan_id, str(req.url), req.max_depth, req.max_pages))

    return result


async def _run_scan_task(loop, scan_id: str, url: str, max_depth: int, max_pages: int):
    result = store.get(scan_id)
    result.status = ScanStatus.RUNNING
    store.save(result)
    _publish(scan_id, {"type": "status", "status": "running"})

    def on_finding(raw: dict):
        finding = Finding(**raw)
        current = store.get(scan_id)
        current.findings.append(finding)
        store.save(current)
        loop.call_soon_threadsafe(
            _publish, scan_id, {"type": "finding", "finding": finding.model_dump(mode="json")}
        )

    try:
        summary = await loop.run_in_executor(
            None, lambda: run_scan(url, max_depth, max_pages, on_finding)
        )
        current = store.get(scan_id)
        current.pages_crawled = summary["pages_crawled"]
        current.status = ScanStatus.COMPLETED
        current.finished_at = datetime.now(timezone.utc)
        store.save(current)
        _publish(scan_id, {"type": "status", "status": "completed"})
    except Exception:
        logger.exception("Scan %s failed", scan_id)
        current = store.get(scan_id)
        current.status = ScanStatus.FAILED
        current.finished_at = datetime.now(timezone.utc)
        store.save(current)
        _publish(scan_id, {"type": "status", "status": "failed"})


@router.get("/scan/{scan_id}", response_model=ScanResult)
async def get_scan(scan_id: str):
    result = store.get(scan_id)
    if not result:
        raise HTTPException(status_code=404, detail="Scan not found")
    return result


@router.get("/scan/{scan_id}/report.pdf")
async def get_scan_report(scan_id: str):
    result = store.get(scan_id)
    if not result:
        raise HTTPException(status_code=404, detail="Scan not found")
    if result.status != ScanStatus.COMPLETED:
        raise HTTPException(status_code=409, detail="Scan not yet completed")
    pdf_bytes = build_pdf(result)
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="scan-{scan_id}.pdf"'},
    )


@router.websocket("/ws/{scan_id}")
async def scan_ws(websocket: WebSocket, scan_id: str):
    await websocket.accept()
    q = _subscribe(scan_id)
    try:
        # Replay current state first so late-connecting clients aren't lost
        existing = store.get(scan_id)
        if existing:
            await websocket.send_json({"type": "status", "status": existing.status.value})
            for f in existing.findings:
                await websocket.send_json({"type": "finding", "finding": f.model_dump(mode="json")})

        while True:
            message = await q.get()
            await websocket.send_json(message)
            if message.get("type") == "status" and message.get("status") in ("completed", "failed"):
                break
    except WebSocketDisconnect:
        pass
    finally:
        _unsubscribe(scan_id, q)
