from .master import verify_password, save_master_hash, is_vault_initialized
from .storage import save_secret, load_secret, list_secrets

# Состояние сессии — ключ хранится в памяти пока vault разблокирован
_session_key: bytes | None = None

def unlock(password: str) -> bool:
    global _session_key
    from .cipher import derive_key
    if not is_vault_initialized():
        # Первый запуск — сохранить пароль и создать ключ
        save_master_hash(password)
        _session_key = derive_key(password)
        return True
    if verify_password(password):
        _session_key = derive_key(password)
        return True
    return False

def lock():
    global _session_key
    _session_key = None

def save_secret(name: str, value: str):
    if _session_key is None:
        raise RuntimeError("Vault заблокирован. Сначала вызови unlock(password).")
    from .storage import save_secret as _save
    _save(name, value, _session_key)

def load_secret(name: str) -> str:
    if _session_key is None:
        raise RuntimeError("Vault заблокирован. Сначала вызови unlock(password).")
    from .storage import load_secret as _load
    return _load(name, _session_key)