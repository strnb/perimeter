import os
import base64
from pathlib import Path
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from .salt import get_salt  # импортируем общую функцию

VAULT_DIR = Path("vault")

def derive_key(password: str) -> bytes:
    salt = get_salt()  # теперь берём из salt.py
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