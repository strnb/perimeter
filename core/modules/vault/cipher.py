import os
import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

from . import master


def _salt_file():
    # salt лежит рядом с .master в папке проекта, а не в cwd:
    # иначе ключ зависит от директории запуска и секреты не читаются
    return master.VAULT_DIR / ".salt"


def _get_or_create_salt() -> bytes:
    master.VAULT_DIR.mkdir(exist_ok=True)
    salt_file = _salt_file()
    if not salt_file.exists():
        # 'xb' — создать только если файла ещё нет: два процесса не перезапишут соль
        try:
            with open(salt_file, "xb") as f:
                f.write(os.urandom(16))
        except FileExistsError:
            pass
    return salt_file.read_bytes()

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
