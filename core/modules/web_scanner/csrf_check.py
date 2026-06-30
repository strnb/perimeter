import logging
from typing import Optional

import httpx

from core.modules.web_scanner.types import WebCheck, WebFinding

logger = logging.getLogger(__name__)

CHECK_NAME = "CSRF"
TARGET_PATH = "/vulnerabilities/csrf/"
REQUEST_TIMEOUT = 3.0
CSRF_SIGNALS = ("user_token", "csrf_token", "xsrf", "authenticity_token")


async def run_check(client: httpx.AsyncClient, base_url: str) -> Optional[WebFinding]:
    """
    Сканирует страницу безопасности/смены пароля на признаки отсутствия CSRF-защиты.
    """
    target_url = f"{base_url}{TARGET_PATH}"

    try:
        response = await client.get(target_url, timeout=REQUEST_TIMEOUT)
        if response.status_code != 200:
            return None

        html_content = response.text.lower()
        protected = any(token in html_content for token in CSRF_SIGNALS)

        if not protected:
            return WebFinding(
                url=target_url,
                vuln_type="CSRF (Cross-Site Request Forgery)",
                severity="MEDIUM",
                detail=(
                    "Форма изменения критических параметров пользователя не содержит Anti-CSRF токенов. "
                    "Возможна подделка запроса."
                ),
                kb_id="VULN-035",
            )
    except Exception as exc:
        logger.error("Ошибка в плагине CSRF: %s", exc)

    return None


CHECK = WebCheck(name=CHECK_NAME, run=run_check)
