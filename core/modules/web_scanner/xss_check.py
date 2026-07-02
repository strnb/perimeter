import logging
from typing import Optional

import httpx

from core.modules.web_scanner.types import WebCheck, WebFinding
from core.modules.web_scanner.config import ACTIVE_PROFILE

logger = logging.getLogger(__name__)

CHECK_NAME = "Reflected XSS"
REQUEST_TIMEOUT = 3.0
PAYLOAD = "PerimeterXSS'\"<script>alert(1)</script>"


async def run_check(client: httpx.AsyncClient, base_url: str) -> Optional[WebFinding]:
    """
    Reflected XSS: отправляем payload в параметр, проверяем что он
    отражается в теле ответа без экранирования.
    Теперь путь и параметр берутся из конфига таргета, а не хардкода.
    """
    profile = ACTIVE_PROFILE
    target_url = f"{base_url}{profile.xss_path}"

    try:
        response = await client.get(
            target_url,
            params={profile.xss_param: PAYLOAD},
            timeout=REQUEST_TIMEOUT
        )
        if response.status_code != 200:
            return None

        # Проверяем что payload НЕ был экранирован (< не превратилось в &lt;)
        if PAYLOAD in response.text or "<script>alert(1)</script>" in response.text:
            return WebFinding(
                url=f"{target_url}?{profile.xss_param}={PAYLOAD}",
                vuln_type="Reflected XSS",
                severity="HIGH",
                detail=(
                    f"Параметр '{profile.xss_param}' отражается в ответе без санитизации. "
                    f"Браузер выполнит произвольный JS. Payload: {PAYLOAD[:40]}..."
                ),
                kb_id="VULN-036",
            )
    except Exception as exc:
        logger.error("Ошибка в плагине XSS: %s", exc)

    return None


CHECK = WebCheck(name=CHECK_NAME, run=run_check)