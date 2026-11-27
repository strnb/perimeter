import json
import base64
from pathlib import Path
from .cipher import encrypt, decrypt
from .master import VAULT_DIR, write_private

STORAGE_FILE = VAULT_DIR / "encrypted.json"

def _load_storage() -> dict:
    if not STORAGE_FILE.exists():
        return {}
    return json.loads(STORAGE_FILE.read_text(encoding="utf-8"))

# shortcut: две одновременные записи теряют одно изменение — блокировка нужна,
# только если vault начнут использовать несколько процессов сразу
def _save_storage(data: dict):
    write_private(STORAGE_FILE, json.dumps(data, indent=2).encode())

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
