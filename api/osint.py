"""OSINT — WHOIS + DNS + пассивные источники + проверки конфигурации."""

import logging

logger = logging.getLogger(__name__)

try:
    from core.modules.scanner.osint import run_osint
    _OSINT_AVAILABLE = True
except ImportError:
    _OSINT_AVAILABLE = False
    logger.warning("OSINT module not available")


async def run_osint_report(
    domain: str,
    wordlist_path: str = None,
    **options,
) -> dict:
    """options: active, sources, concurrency, use_cache, cache_dir."""
    if not _OSINT_AVAILABLE:
        return {"error": "OSINT module not available"}
    try:
        return await run_osint(domain, wordlist_path=wordlist_path, **options)
    except ValueError as exc:
        return {"error": str(exc)}
    except Exception as exc:
        logger.error("run_osint_report error: %s", exc)
        return {"error": str(exc)}
