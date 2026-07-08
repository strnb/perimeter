"""
web_pipeline.py

Главная точка входа Web Scanner.
"""

import asyncio
import logging
from typing import Dict, Iterable, List, Optional

import httpx

from core.modules.web_scanner.registry import CHECKS
from core.modules.web_scanner.tech_detector import detect_technologies
from core.modules.web_scanner.headers_checker import check_headers
from core.modules.web_scanner.types import WebFinding

logger = logging.getLogger(__name__)


async def _run_checks(
    client: httpx.AsyncClient,
    base_url: str,
) -> List[WebFinding]:
    """
    Запускает все проверки из registry.py.
    """

    tasks = [
        check.run(client, base_url)
        for check in CHECKS
    ]

    results = await asyncio.gather(
        *tasks,
        return_exceptions=True,
    )

    findings: List[WebFinding] = []

    for check, result in zip(CHECKS, results):

        if isinstance(result, Exception):

            logger.error(
                "[Web Scanner] %s: %s",
                check.name,
                result,
            )

            continue

        if isinstance(result, WebFinding):
            findings.append(result)

    return findings


def _serialize_findings(
    findings: Iterable[WebFinding],
) -> List[Dict]:
    """
    Преобразует WebFinding в словарь.
    """

    return [
        finding.as_dict()
        for finding in findings
    ]


async def run_web_assessment(
    target_ip: str,
    port: int,
    cookies: Optional[Dict[str, str]] = None,
) -> dict:
    """
    Главная точка входа Web Scanner.
    """

    scheme = "https" if port == 443 else "http"

    base_url = f"{scheme}://{target_ip}:{port}"

    async with httpx.AsyncClient(
        cookies=cookies,
        follow_redirects=False,
        verify=False,
        timeout=15,
    ) as client:

        logger.info(
            "[Web Scanner] Проверка %s",
            base_url,
        )

        findings = await _run_checks(
            client,
            base_url,
        )

    #
    # Дополнительные проверки
    #

    technologies = await detect_technologies(
        target_ip,
        port,
    )

    headers = await check_headers(
        target_ip,
        port,
    )

    return {
        "host": target_ip,
        "port": port,
        "protocol": scheme,
        "findings": _serialize_findings(findings),
        "technologies": technologies,
        "headers": headers,
    }