# core/modules/web_scanner/open_redirect.py
import logging
import httpx

logger = logging.getLogger(__name__)


async def run_check(client: httpx.AsyncClient, base_url: str) -> dict | None:
    """
    Проверяет, уязвимо ли приложение к Open HTTP Redirect.
    """
    target_url = f"{base_url}/vulnerabilities/redirect/"
    external_domain = "http://example.com"

    try:
        # Важно: follow_redirects=False позволяет прочитать заголовок Location до перехода
        response = await client.get(
            target_url,
            params={"redirect": external_domain},
            follow_redirects=False,
            timeout=3.0
        )

        # Если статус ответа 301/302 (Redirect) и Location ведет на внешний домен
        if response.status_code in [301, 302] and response.headers.get("Location") == external_domain:
            return {
                "url": target_url,
                "vuln_type": "Open HTTP Redirect",
                "severity": "LOW",
                "detail": f"Приложение принимает внешние адреса в параметрах и перенаправляет пользователя на сторонний ресурс ({external_domain}) без валидации.",
                "kb_id": "VULN-024"
            }
    except Exception as e:
        logger.error(f"Ошибка в плагине Open Redirect: {e}")

    return None