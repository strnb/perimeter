"""
headers_checker.py

Проверка HTTP Security Headers.
"""

from __future__ import annotations

import logging
from typing import Dict, List

import httpx

logger = logging.getLogger(__name__)


REQUIRED_HEADERS: Dict[str, Dict[str, str]] = {
    "Content-Security-Policy": {
        "severity": "high",
        "recommendation": (
            "Добавить Content-Security-Policy для защиты от XSS."
        ),
    },
    "Strict-Transport-Security": {
        "severity": "high",
        "recommendation": (
            "Добавить Strict-Transport-Security для принудительного использования HTTPS."
        ),
    },
    "X-Frame-Options": {
        "severity": "medium",
        "recommendation": (
            "Добавить X-Frame-Options для защиты от Clickjacking."
        ),
    },
    "X-Content-Type-Options": {
        "severity": "medium",
        "recommendation": (
            "Добавить X-Content-Type-Options: nosniff."
        ),
    },
    "Referrer-Policy": {
        "severity": "low",
        "recommendation": (
            "Добавить Referrer-Policy для ограничения передачи Referer."
        ),
    },
    "Permissions-Policy": {
        "severity": "low",
        "recommendation": (
            "Добавить Permissions-Policy для ограничения возможностей браузера."
        ),
    },
}


async def check_headers(
    host: str,
    port: int,
) -> List[Dict[str, str]]:
    """
    Проверяет наличие HTTP Security Headers.

    Args:
        host: IP или домен
        port: HTTP-порт

    Returns:
        list[dict]
    """

    findings: List[Dict[str, str]] = []

    scheme = "https" if port == 443 else "http"

    url = f"{scheme}://{host}:{port}"

    try:

        async with httpx.AsyncClient(
            timeout=10,
            verify=False,
            follow_redirects=True,
        ) as client:

            response = await client.get(url)

    except Exception as e:

        logger.warning(
            "[Headers Checker] %s : %s",
            url,
            e,
        )

        return findings

    headers = response.headers

    for header, info in REQUIRED_HEADERS.items():

        if header not in headers:

            findings.append(
                {
                    "header": header,
                    "severity": info["severity"],
                    "recommendation": info["recommendation"],
                }
            )

    logger.info(
        "[Headers Checker] %s -> отсутствует %s заголовков",
        host,
        len(findings),
    )

    return findings