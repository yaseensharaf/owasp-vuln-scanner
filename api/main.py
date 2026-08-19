from __future__ import annotations

import logging

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles

from api.routes.scan import router as scan_router

logging.basicConfig(level=logging.INFO)

app = FastAPI(
    title="OWASP Top 10 Vulnerability Scanner",
    description=(
        "Scans a target web application you own or are explicitly authorized "
        "to test, for common OWASP Top 10 issues. Not for use against systems "
        "you do not have permission to scan."
    ),
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # tighten this for real deployments
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(scan_router, prefix="/api")


@app.get("/health")
async def health():
    return {"status": "ok"}


# Serve the simple frontend dashboard
app.mount("/", StaticFiles(directory="frontend", html=True), name="frontend")
