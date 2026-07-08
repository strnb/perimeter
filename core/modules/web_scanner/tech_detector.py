"""
tech_detector.py

Определение технологий веб-приложения.

Анализируются:

- Server
- X-Powered-By
- HTML
"""

from __future__ import annotations

import logging
import re
from typing import List

import httpx

logger = logging.getLogger(__name__)


def _add(technologies: list[str], value: str) -> None:
    """
    Добавляет технологию без дубликатов.
    """
    if value and value not in technologies:
        technologies.append(value)


async def detect_technologies(
    host: str,
    port: int,
) -> List[str]:
    """
    Определение технологий веб-сервера.

    Returns
    -------
    list[str]
    """

    technologies: List[str] = []

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
            "[Technology Detector] %s : %s",
            url,
            e,
        )

        return technologies

    headers = response.headers

    body = response.text.lower()

    #
    # ---------------------------------------------------------
    # SERVER
    # ---------------------------------------------------------
    #

    server = headers.get("Server")

    if server:

        #
        # Apache/2.4.58
        #

        match = re.search(
            r"apache/?([\d\.]*)",
            server,
            re.I,
        )

        if match:

            version = match.group(1)

            if version:
                _add(
                    technologies,
                    f"Apache {version}",
                )
            else:
                _add(
                    technologies,
                    "Apache",
                )

        #
        # nginx/1.18
        #

        match = re.search(
            r"nginx/?([\d\.]*)",
            server,
            re.I,
        )

        if match:

            version = match.group(1)

            if version:
                _add(
                    technologies,
                    f"Nginx {version}",
                )
            else:
                _add(
                    technologies,
                    "Nginx",
                )

        #
        # IIS
        #

        match = re.search(
            r"iis/?([\d\.]*)",
            server,
            re.I,
        )

        if match:

            version = match.group(1)

            if version:
                _add(
                    technologies,
                    f"Microsoft IIS {version}",
                )
            else:
                _add(
                    technologies,
                    "Microsoft IIS",
                )

    #
    # ---------------------------------------------------------
    # X-Powered-By
    # ---------------------------------------------------------
    #

    powered = headers.get(
        "X-Powered-By",
        "",
    )

    if powered:

        #
        # PHP/7.4
        #

        match = re.search(
            r"php/?([\d\.]*)",
            powered,
            re.I,
        )

        if match:

            version = match.group(1)

            if version:
                _add(
                    technologies,
                    f"PHP {version}",
                )
            else:
                _add(
                    technologies,
                    "PHP",
                )

        #
        # ASP.NET
        #

        if ".net" in powered.lower():

            _add(
                technologies,
                "ASP.NET",
            )

    #
    # ---------------------------------------------------------
    # HTML
    # ---------------------------------------------------------
    #

    if "__next_data__" in body:

        _add(
            technologies,
            "Next.js",
        )

    elif "react" in body:

        _add(
            technologies,
            "React",
        )

    if "__vue_app__" in body:

        _add(
            technologies,
            "Vue.js",
        )

    if "csrfmiddlewaretoken" in body:

        _add(
            technologies,
            "Django",
        )

    if "fastapi" in body:

        _add(
            technologies,
            "FastAPI",
        )

    #
    # ---------------------------------------------------------
    # Дополнительные популярные технологии
    # ---------------------------------------------------------
    #

    if "wp-content" in body:

        _add(
            technologies,
            "WordPress",
        )

    if "laravel" in body:

        _add(
            technologies,
            "Laravel",
        )

    if "flask" in body:

        _add(
            technologies,
            "Flask",
        )

    logger.info(
        "[Technology Detector] %s -> %s",
        host,
        ", ".join(technologies) if technologies else "Unknown",
    )

    return technologies