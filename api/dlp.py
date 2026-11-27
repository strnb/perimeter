"""DLP — поиск секретов в папке (модуль Дамира)."""

import logging

from .knowledge import enrich_finding

logger = logging.getLogger(__name__)

try:
    from core.modules.dlp import run_scan as _dlp_run_scan
    _DLP_AVAILABLE = True
except ImportError:
    _DLP_AVAILABLE = False
    logger.warning("DLP module not available")


def mask_secret(value: str) -> str:
    """Оставляет начало секрета для опознания, остальное скрывает."""
    value = str(value)
    return value[:4] + "…" if len(value) > 8 else "…"


def scan_dlp(path: str, show_secrets: bool = False, stats: dict | None = None,
             git: bool = False, git_depth: int = 0) -> list[dict]:
    """Запускает DLP-сканирование папки path.

    git=True добавляет скан истории репозитория: секреты, удалённые из кода,
    но оставшиеся в прошлых коммитах.
    По умолчанию значения секретов маскируются: отчёт могут переслать дальше.
    """
    if not _DLP_AVAILABLE:
        return [{"error": "DLP module not available"}]

    raw = _dlp_run_scan(path, stats=stats, git_history=git, git_depth=git_depth)
    findings = [enrich_finding(f) for f in raw]
    if not show_secrets:
        for f in findings:
            if f.get("value") and f.get("secret"):
                f["value"] = mask_secret(f["value"])
    return findings
