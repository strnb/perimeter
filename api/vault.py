"""Crypto Vault — шифрованное хранилище секретов (модуль Дамира)."""

import logging
from typing import Optional

logger = logging.getLogger(__name__)

try:
    from core.modules.vault import (
        unlock as _vault_unlock,
        lock as _vault_lock,
        save_secret as _vault_save,
        load_secret as _vault_load,
        list_secrets as _vault_list,
        is_vault_initialized as _vault_initialized,
    )
    _VAULT_AVAILABLE = True
except ImportError:
    _VAULT_AVAILABLE = False
    logger.warning("Vault module not available")


def vault_unlock(password: str) -> bool:
    if not _VAULT_AVAILABLE:
        return False
    try:
        return _vault_unlock(password)
    except Exception as e:
        logger.error(f"vault_unlock error: {e}")
        return False


def vault_lock():
    if _VAULT_AVAILABLE:
        _vault_lock()


def vault_save(name: str, value: str) -> bool:
    if not _VAULT_AVAILABLE:
        return False
    try:
        _vault_save(name, value)
        return True
    except Exception as e:
        logger.error(f"vault_save error: {e}")
        return False


def vault_load(name: str) -> Optional[str]:
    if not _VAULT_AVAILABLE:
        return None
    try:
        return _vault_load(name)
    except Exception as e:
        logger.error(f"vault_load error: {e}")
        return None


def vault_list() -> list[str]:
    if not _VAULT_AVAILABLE:
        return []
    try:
        return _vault_list()
    except Exception as e:
        logger.error(f"vault_list error: {e}")
        return []


def vault_is_initialized() -> bool:
    if not _VAULT_AVAILABLE:
        return False
    return _vault_initialized()
