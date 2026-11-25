"""
Access-controlled, encrypted local object storage for raw uploaded lab reports.
Enforces encryption at rest and auto-expiry retention metadata (S3-compatible abstraction).
"""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Tuple

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from core.config import RAW_FILE_TTL_DAYS, STORAGE_DIR
from core.database.models import RawUpload
from core.security.crypto import VaultCrypto, sha256_bytes


def store_encrypted_raw_file(raw_bytes: bytes, extension: str) -> Tuple[str, str, str, datetime]:
    """
    Encrypts raw file bytes and writes them to STORAGE_DIR.
    Returns (upload_id, storage_uri, sha256_hex, expires_at).
    """
    STORAGE_DIR.mkdir(parents=True, exist_ok=True)
    upload_id = f"upl-{uuid.uuid4().hex[:12]}"
    safe_ext = "".join(c for c in extension.lower() if c.isalnum())[:8] or "bin"
    target_path = STORAGE_DIR / f"{upload_id}.{safe_ext}.enc"

    sha256_hex = sha256_bytes(raw_bytes)
    encrypted_bytes = VaultCrypto.encrypt_bytes(raw_bytes)
    target_path.write_bytes(encrypted_bytes)

    expires_at = datetime.now(timezone.utc) + timedelta(days=RAW_FILE_TTL_DAYS)
    return upload_id, str(target_path), sha256_hex, expires_at


def read_decrypted_raw_file(storage_uri: str) -> bytes:
    path = Path(storage_uri)
    if not path.exists():
        raise FileNotFoundError("Encrypted upload artifact not found or already expired.")
    return VaultCrypto.decrypt_bytes(path.read_bytes())


async def purge_expired_uploads(db: AsyncSession) -> int:
    """Deletes expired encrypted objects from storage and DB."""
    now = datetime.now(timezone.utc)
    res = await db.execute(select(RawUpload).where(RawUpload.expires_at < now))
    expired = res.scalars().all()
    count = 0
    for item in expired:
        path = Path(item.storage_uri)
        if path.exists():
            path.unlink(missing_ok=True)
        await db.delete(item)
        count += 1
    if count:
        await db.commit()
    return count
