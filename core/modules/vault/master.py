import base64
from pathlib import Path
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from .salt import get_salt

VAULT_DIR = Path("vault")
MASTER_FILE = VAULT_DIR / ".master"

def hash_password(password: str) -> str:
    salt = get_salt()
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=480000,  # те же итерации что в cipher.py
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode())).decode()

def save_master_hash(password: str):
    VAULT_DIR.mkdir(exist_ok=True)
    MASTER_FILE.write_text(hash_password(password))

def verify_password(password: str) -> bool:
    if not is_vault_initialized():
        return False
    saved_hash = MASTER_FILE.read_text().strip()
    return hash_password(password) == saved_hash

def is_vault_initialized() -> bool:
    return MASTER_FILE.exists()