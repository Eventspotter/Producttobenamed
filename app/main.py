"""
Main FastAPI Application Entrypoint for Phase 0 + Phase 1.
Serves API v1 and the PulseVault dashboard.
"""

from __future__ import annotations

from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from api.v1 import router as api_v1_router
from core.database.session import init_db

BASE_DIR = Path(__file__).resolve().parent.parent
DASHBOARD_PATH = BASE_DIR / "pulsevault.html"


@asynccontextmanager
async def lifespan(_app: FastAPI):
    await init_db()
    yield


app = FastAPI(
    title="PulseVault — Phase 1 Health Ingestion & Family Vault",
    description=(
        "Local multi-profile health ingestion, consent records, unit normalization, "
        "human review, encrypted storage, and a FairPulse cohort bridge."
    ),
    version="1.0.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(api_v1_router)


@app.get("/", include_in_schema=False)
async def serve_dashboard():
    return FileResponse(DASHBOARD_PATH)
