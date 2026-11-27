import hashlib
import hmac
import os
import tempfile
from pathlib import Path

from core.paths import app_data_dir

# В репозитории/editable-установке vault лежит рядом с кодом, как раньше.
# После обычного pip install site-packages только для чтения — уходим в ~/.perimeter.
_REPO_ROOT = Path(__file__).resolve().parents[3]
if (_REPO_ROOT / "knowledge_base").is_dir():
    VAULT_DIR = _REPO_ROOT / "vault"
else:
    VAULT_DIR = app_data_dir() / "vault"
MASTER_FILE = VAULT_DIR / ".master"

ITERATIONS = 480_000


def write_private(path: Path, data: bytes):
    """Атомарная запись с правами 0600: падение не оставит пустой файл."""
    path.parent.mkdir(exist_ok=True)
    if os.name != "nt":
        os.chmod(path.parent, 0o700)
    fd, tmp = tempfile.mkstemp(dir=str(path.parent), prefix=path.name + ".")
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data)
        if os.name != "nt":
            os.chmod(tmp, 0o600)
        os.replace(tmp, path)
    except BaseException:
        if os.path.exists(tmp):
            os.unlink(tmp)
        raise


def hash_password(password: str) -> str:
    """Старый формат (несолёный SHA-256) — только для чтения старых vault."""
    return hashlib.sha256(password.encode()).hexdigest()


def _derive(password: str, salt: bytes, iterations: int) -> bytes:
    return hashlib.pbkdf2_hmac("sha256", password.encode(), salt, iterations)


def save_master_hash(password: str):
    salt = os.urandom(16)
    digest = _derive(password, salt, ITERATIONS).hex()
    write_private(MASTER_FILE, f"pbkdf2_sha256${ITERATIONS}${salt.hex()}${digest}".encode())


def verify_password(password: str) -> bool:
    if not is_vault_initialized():
        return False
    saved = MASTER_FILE.read_text().strip()

    if saved.startswith("pbkdf2_sha256$"):
        _, iterations, salt_hex, digest = saved.split("$")
        actual = _derive(password, bytes.fromhex(salt_hex), int(iterations)).hex()
        return hmac.compare_digest(actual, digest)

    # Vault, созданный старой версией: сверяем по-старому и сразу обновляем формат
    ok = hmac.compare_digest(hash_password(password), saved)
    if ok:
        save_master_hash(password)
    return ok


def is_vault_initialized() -> bool:
    return MASTER_FILE.exists()
