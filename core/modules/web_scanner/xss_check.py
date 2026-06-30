import logging
from typing import Optional

import httpx

from core.modules.web_scanner.types import WebCheck, WebFinding

logger = logging.getLogger(__name__)

CHECK_NAME = "Reflected XSS"
TARGET_PATH = "/vulnerabilities/xss_r/"
REQUEST_TIMEOUT = 3.0
PAYLOAD = "PerimeterXSS'\"<>"


async def run_check(client: httpx.AsyncClient, base_url: str) -> Optional[WebFinding]:
    """
    Тестирует веб-приложение на наличие уязвимости Reflected XSS.
    """
    target_url = f"{base_url}{TARGET_PATH}"

    try:
        response = await client.get(target_url, params={"name": PAYLOAD}, timeout=REQUEST_TIMEOUT)
        if response.status_code != 200:
            return None

        # Если сервер возвращает спецсимволы без санитизации (не превратил < > в < >)
        if PAYLOAD in response.text:
            return WebFinding(
                url=target_url,
                vuln_type="Reflected XSS",
                severity="HIGH",
                detail=(
                    "Входные данные отражаются сервером без должной фильтрации. "
                    f"Браузер может выполнить произвольный JS-код. Payload: {PAYLOAD}"
                ),
                kb_id="VULN-036",
            )
    except Exception as exc:
        logger.error("Ошибка в плагине XSS: %s", exc)

    return None


CHECK = WebCheck(name=CHECK_NAME, run=run_check)
