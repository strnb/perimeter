import os
from pathlib import Path

VAULT_DIR = Path("vault")
SALT_FILE = VAULT_DIR / ".salt"

def get_salt() -> bytes:
    VAULT_DIR.mkdir(exist_ok=True)
    if SALT_FILE.exists():
        return SALT_FILE.read_bytes()
    salt = os.urandom(16)
    SALT_FILE.write_bytes(salt)
    return salt