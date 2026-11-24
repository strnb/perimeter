"""OSINT — WHOIS + DNS + перебор поддоменов (модуль Демьяна)."""

import logging

from .paths import DEFAULT_WORDLIST

logger = logging.getLogger(__name__)

try:
    from core.modules.scanner.osint import run_osint
    _OSINT_AVAILABLE = True
except ImportError:
    _OSINT_AVAILABLE = False
    logger.warning("OSINT module not available")


async def run_osint_report(
    domain: str,
    wordlist_path: str = DEFAULT_WORDLIST,
) -> dict:
    if not _OSINT_AVAILABLE:
        return {"error": "OSINT module not available"}
    try:
        return await run_osint(domain, wordlist_path=wordlist_path)
    except Exception as e:
        logger.error(f"run_osint_report error: {e}")
        return {"error": str(e)}
