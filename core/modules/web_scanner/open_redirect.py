import logging
from typing import Optional

import httpx

from core.modules.web_scanner.types import WebCheck, WebFinding

logger = logging.getLogger(__name__)

CHECK_NAME = "Open Redirect"
TARGET_PATH = "/vulnerabilities/redirect/"
REQUEST_TIMEOUT = 3.0
EXTERNAL_DOMAIN = "http://example.com"


async def run_check(client: httpx.AsyncClient, base_url: str) -> Optional[WebFinding]:
    """
    Проверяет, уязвимо ли приложение к Open HTTP Redirect.
    """
    target_url = f"{base_url}{TARGET_PATH}"

    try:
        # Важно: follow_redirects=False позволяет прочитать заголовок Location до перехода
        response = await client.get(
            target_url,
            params={"redirect": EXTERNAL_DOMAIN},
            follow_redirects=False,
            timeout=REQUEST_TIMEOUT,
        )

        # Если статус ответа 301/302 (Redirect) и Location ведет на внешний домен
        if response.status_code in (301, 302) and response.headers.get("Location") == EXTERNAL_DOMAIN:
            return WebFinding(
                url=target_url,
                vuln_type="Open HTTP Redirect",
                severity="LOW",
                detail=(
                    "Приложение принимает внешние адреса в параметрах и перенаправляет пользователя "
                    f"на сторонний ресурс ({EXTERNAL_DOMAIN}) без валидации."
                ),
                kb_id="VULN-038",
            )
    except Exception as exc:
        logger.error("Ошибка в плагине Open Redirect: %s", exc)

    return None


CHECK = WebCheck(name=CHECK_NAME, run=run_check)
