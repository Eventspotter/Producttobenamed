"""
Encryption-at-rest, cryptographic hashing, and PII redaction utilities.
Protects stored normalized records and raw uploaded lab files under DPDP / HIPAA.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
from typing import Any, Dict

from cryptography.fernet import Fernet

from core.config import DEV_KEY_PATH


def _load_or_create_key() -> bytes:
    env_key = os.getenv("VAULT_ENCRYPTION_KEY")
    if env_key:
        return env_key.encode("utf-8")

    if DEV_KEY_PATH.exists():
        return DEV_KEY_PATH.read_bytes().strip()

    key = Fernet.generate_key()
    DEV_KEY_PATH.write_bytes(key)
    try:
        os.chmod(DEV_KEY_PATH, 0o600)
    except OSError:
        pass
    return key


class VaultCrypto:
    """Symmetric authenticated encryption (Fernet AES-128-CBC + HMAC-SHA256) for vault data at rest."""

    _fernet: Fernet | None = None

    @classmethod
    def _cipher(cls) -> Fernet:
        if cls._fernet is None:
            cls._fernet = Fernet(_load_or_create_key())
        return cls._fernet

    @classmethod
    def encrypt_bytes(cls, data: bytes) -> bytes:
        return cls._cipher().encrypt(data)

    @classmethod
    def decrypt_bytes(cls, token: bytes) -> bytes:
        return cls._cipher().decrypt(token)

    @classmethod
    def encrypt_json(cls, payload: Dict[str, Any]) -> str:
        raw = json.dumps(payload, default=str).encode("utf-8")
        return cls.encrypt_bytes(raw).decode("utf-8")

    @classmethod
    def decrypt_json(cls, encrypted_str: str) -> Dict[str, Any]:
        raw = cls.decrypt_bytes(encrypted_str.encode("utf-8"))
        return json.loads(raw.decode("utf-8"))


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def hash_identifier(value: str) -> str:
    """One-way salted SHA-256 hash for IP addresses and non-reversible audit references."""
    return hashlib.sha256(f"fp-salt::{value}".encode("utf-8")).hexdigest()[:24]


_PII_PATTERNS = [
    (re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"), "[REDACTED_EMAIL]"),
    (re.compile(r"(?:\+?91[-\s]?)?[6-9]\d{9}\b"), "[REDACTED_PHONE]"),
    (re.compile(r"\b\d{3}[-.\s]?\d{3}[-.\s]?\d{4}\b"), "[REDACTED_PHONE]"),
    (re.compile(r"\b\d{4}\s?\d{4}\s?\d{4}\b"), "[REDACTED_GOV_ID]"),
    (re.compile(r"\b\d{3}-\d{2}-\d{4}\b"), "[REDACTED_SSN]"),
    (
        re.compile(
            r"(?im)^(?:patient\s*name|name|mrn|uhid|reg\.?\s*no\.?)\s*[:\-]\s*[^\n\r]+$"
        ),
        "[REDACTED_IDENTITY_LINE]",
    ),
]


def redact_pii(text: str) -> str:
    """Strips direct identifiers before any text leaves the secure boundary."""
    cleaned = text
    for pattern, replacement in _PII_PATTERNS:
        cleaned = pattern.sub(replacement, cleaned)
    return cleaned
