"""API v1 router aggregator."""

from fastapi import APIRouter

from .audit import router as audit_router
from .ingestion import router as ingestion_router
from .profiles import router as profiles_router

router = APIRouter(prefix="/api/v1")
router.include_router(profiles_router)
router.include_router(ingestion_router)
router.include_router(audit_router)
