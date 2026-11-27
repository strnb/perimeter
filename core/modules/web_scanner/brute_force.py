import asyncio
import logging
from typing import Optional

import httpx

from core.modules.web_scanner.types import WebCheck, WebFinding

logger = logging.getLogger(__name__)

CHECK_NAME = "Brute Force"
TARGET_PATH = "/vulnerabilities/brute/"
ATTEMPTS = 10
REQUEST_TIMEOUT = 2.0


def _build_attempts() -> list[dict[str, str]]:
    return [
        {"username": "admin", "password": f"fake_pass_{i}", "Login": "Login"}
        for i in range(ATTEMPTS)
    ]


async def run_check(client: httpx.AsyncClient, base_url: str) -> Optional[WebFinding]:
    """
    Проверяет отсутствие блокировки аккаунта (Rate Limiting) и капчи в DVWA.
    """
    target_url = f"{base_url}{TARGET_PATH}"
    tasks = [client.get(target_url, params=params, timeout=REQUEST_TIMEOUT) for params in _build_attempts()]

    try:
        responses = await asyncio.gather(*tasks, return_exceptions=True)
        # DVWA отвечает 200 и на неудачный вход, поэтому 200 сам по себе — не успех.
        # Блокировку видно по 429/403, а «нет лимита» — когда все попытки обработаны.
        blocked = any(isinstance(r, httpx.Response) and r.status_code in (429, 403)
                      for r in responses)
        processed = sum(1 for r in responses if isinstance(r, httpx.Response) and r.status_code == 200)

        if not blocked and processed == ATTEMPTS:
            return WebFinding(
                url=target_url,
                vuln_type="Brute Force / No Rate Limiting",
                severity="HIGH",
                detail="Форма логина обработала 10 попыток подряд без блокировки, задержки и CAPTCHA.",
                kb_id="VULN-034",
            )
    except Exception as exc:
        logger.error("Ошибка в плагине Brute Force: %s", exc)

    return None


CHECK = WebCheck(name=CHECK_NAME, run=run_check)
