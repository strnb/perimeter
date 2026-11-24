"""Web Scanner (L7) — аудит веб-уязвимостей."""

import logging
from typing import Optional

from .knowledge import enrich_finding

logger = logging.getLogger(__name__)

try:
    from core.modules.web_scanner.web_pipeline import run_web_assessment
    _WEB_SCANNER_AVAILABLE = True
except ImportError:
    _WEB_SCANNER_AVAILABLE = False
    logger.warning("Web Scanner module not available")


async def scan_web(
    target_ip: str,
    port: int = 4280,
    cookies: Optional[dict] = None,
) -> list[dict]:
    """
    Асинхронный аудит веб-уязвимостей (L7) с обогащением из базы знаний.
    """
    if not _WEB_SCANNER_AVAILABLE:
        return [{"error": "Web Scanner module not available"}]
    try:
        raw_findings = await run_web_assessment(target_ip, port=port, cookies=cookies)
        return [enrich_finding(f) for f in raw_findings if f]
    except Exception as e:
        logger.error(f"scan_web error: {e}")
        return [{"error": str(e)}]
