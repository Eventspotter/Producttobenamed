"""Application configuration for Phase 0/1 Health Vault."""

from __future__ import annotations

import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
DATABASE_URL = os.getenv("DATABASE_URL", f"sqlite+aiosqlite:///{BASE_DIR / 'health_vault.db'}")
STORAGE_DIR = Path(os.getenv("STORAGE_DIR", str(BASE_DIR / "storage" / "uploads")))
DEV_KEY_PATH = BASE_DIR / ".dev_secret.key"
RAW_FILE_TTL_DAYS = int(os.getenv("RAW_FILE_TTL_DAYS", "30"))
DEFAULT_OWNER_ID = os.getenv("DEFAULT_OWNER_ID", "owner-default-001")
DEFAULT_OWNER_NAME = os.getenv("DEFAULT_OWNER_NAME", "Elisa Nilsson")
