import os
import base64
from pathlib import Path
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

VAULT_DIR = Path("vault")
SALT_FILE = VAULT_DIR / ".salt"

def _get_or_create_salt() -> bytes:
    VAULT_DIR.mkdir(exist_ok=True)
    if SALT_FILE.exists():
        return SALT_FILE.read_bytes()
    salt = os.urandom(16)
    SALT_FILE.write_bytes(salt)
    return salt

def derive_key(password: str) -> bytes:
    salt = _get_or_create_salt()
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=480000,
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode()))

def encrypt(data: str, key: bytes) -> bytes:
    return Fernet(key).encrypt(data.encode())

def decrypt(token: bytes, key: bytes) -> str:
    return Fernet(key).decrypt(token).decode()