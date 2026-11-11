from __future__ import annotations

import os
import re
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from pathlib import Path

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64
import secrets

_MAGIC = b"PFSO-BACKUP-1\n"
_ITERATIONS = 600_000


def _derive_key(passphrase: str, salt: bytes) -> bytes:
    if len(passphrase) < 12:
        raise ValueError("Backup passphrase must contain at least 12 characters.")
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=_ITERATIONS)
    return base64.urlsafe_b64encode(kdf.derive(passphrase.encode("utf-8")))


def encrypt_backup(xml_bytes: bytes, passphrase: str) -> bytes:
    try:
        ET.fromstring(xml_bytes)
    except ET.ParseError as exc:
        raise ValueError("The downloaded configuration is not valid XML; refusing to store it as a backup.") from exc
    salt = secrets.token_bytes(16)
    token = Fernet(_derive_key(passphrase, salt)).encrypt(xml_bytes)
    return _MAGIC + salt + token


def decrypt_backup(blob: bytes, passphrase: str) -> bytes:
    if not blob.startswith(_MAGIC) or len(blob) <= len(_MAGIC) + 16:
        raise ValueError("Not a supported pfSense Orchestrator backup file.")
    offset = len(_MAGIC)
    salt = blob[offset:offset + 16]
    plaintext = Fernet(_derive_key(passphrase, salt)).decrypt(blob[offset + 16:])
    ET.fromstring(plaintext)
    return plaintext


def create_encrypted_backup(ssh, target_host: str, destination: Path, passphrase: str) -> Path:
    """Download /conf/config.xml through SFTP and save only an encrypted local copy."""
    destination = destination.expanduser()
    destination.mkdir(mode=0o700, parents=True, exist_ok=True)
    try:
        os.chmod(destination, 0o700)
    except OSError:
        pass

    sftp = ssh.open_sftp()
    try:
        with sftp.open("/conf/config.xml", "rb") as remote_file:
            raw = remote_file.read()
    finally:
        sftp.close()

    payload = encrypt_backup(raw, passphrase)
    safe_host = re.sub(r"[^A-Za-z0-9_.-]+", "_", target_host)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S_%fZ")
    path = destination / f"{safe_host}_{stamp}.pfso.enc"
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as handle:
        handle.write(payload)
        handle.flush()
        os.fsync(handle.fileno())
    return path
