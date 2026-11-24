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


def scan_dlp(path: str) -> list[dict]:
    """Запускает DLP-сканирование папки path."""
    if not _DLP_AVAILABLE:
        return [{"error": "DLP module not available"}]

    raw = _dlp_run_scan(path)
    return [enrich_finding(f) for f in raw]
