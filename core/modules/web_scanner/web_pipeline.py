import asyncio
import logging
from typing import Dict, Iterable, List, Optional

import httpx

from core.modules.web_scanner.registry import CHECKS
from core.modules.web_scanner.types import WebFinding

async def run_web_assessment(
    target_ip: str,
    port: int,
    cookies: [Dict[str, str]] = None,
):
    """
    Главная точка входа Web Scanner.
    """

    scheme = "https" if port == 443 else "http"

    base_url = f"{scheme}://{target_ip}:{port}"

    async with httpx.AsyncClient(
        cookies=cookies,
        follow_redirects=False,
        verify=False,
    ) as client:

        logger.info(
            "[Web Scanner] Запуск %s модулей для %s",
            len(CHECKS),
            base_url,
        )

        findings = await _run_checks(
            client,
            base_url,
        )

    return _serialize_findings(findings)