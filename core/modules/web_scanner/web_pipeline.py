import asyncio
import logging
from typing import Dict, Iterable, List, Optional

import httpx

from core.modules.web_scanner.registry import CHECKS
from core.modules.web_scanner.types import WebFinding

logger = logging.getLogger(__name__)


async def _run_checks(
    client: httpx.AsyncClient,
    base_url: str,
) -> list[WebFinding]:
    tasks = [check.run(client, base_url) for check in CHECKS]
    results = await asyncio.gather(*tasks, return_exceptions=True)

    findings: list[WebFinding] = []
    for check, result in zip(CHECKS, results):
        if isinstance(result, WebFinding):
            findings.append(result)
        elif isinstance(result, Exception):
            logger.error("[Web Scanner] Ошибка модуля %s: %s", check.name, result)

    return findings


async def run_web_assessment(
    target_ip: str,
    port: int = 4280,
    cookies: Optional[Dict[str, str]] = None,
) -> List[Dict[str, str]]:
    """
    Глобальная точка входа для аудита уязвимостей L7 (Web).
    Запускает все модули в параллельном асинхронном режиме.
    """
    base_url = f"http://{target_ip}:{port}"

    # Единый асинхронный клиент для оптимизации сессий
    async with httpx.AsyncClient(cookies=cookies, follow_redirects=False) as client:
        logger.info(
            "[Web Scanner] Запуск %s веб-модулей для веб-сервера %s",
            len(CHECKS),
            base_url,
        )
        findings = await _run_checks(client, base_url)

    return _serialize_findings(findings)


def _serialize_findings(findings: Iterable[WebFinding]) -> List[Dict[str, str]]:
    return [finding.as_dict() for finding in findings]
