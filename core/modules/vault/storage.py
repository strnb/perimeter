import json
import base64
from pathlib import Path
from .cipher import encrypt, decrypt

VAULT_DIR = Path("vault")
STORAGE_FILE = VAULT_DIR / "encrypted.json"

def _load_storage() -> dict:
    if not STORAGE_FILE.exists():
        return {}
    return json.loads(STORAGE_FILE.read_text())

def _save_storage(data: dict):
    VAULT_DIR.mkdir(exist_ok=True)
    STORAGE_FILE.write_text(json.dumps(data, indent=2))

def save_secret(name: str, value: str, key: bytes):
    data = _load_storage()
    encrypted = encrypt(value, key)
    data[name] = base64.urlsafe_b64encode(encrypted).decode()
    _save_storage(data)

def load_secret(name: str, key: bytes) -> str:
    data = _load_storage()
    if name not in data:
        raise KeyError(f"Секрет '{name}' не найден")
    encrypted = base64.urlsafe_b64decode(data[name])
    return decrypt(encrypted, key)

def list_secrets() -> list[str]:
    return list(_load_storage().keys())