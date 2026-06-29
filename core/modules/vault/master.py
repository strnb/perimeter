import hashlib
from pathlib import Path

VAULT_DIR = Path("vault")
MASTER_FILE = VAULT_DIR / ".master"

def hash_password(password: str) -> str:
    return hashlib.sha256(password.encode()).hexdigest()

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