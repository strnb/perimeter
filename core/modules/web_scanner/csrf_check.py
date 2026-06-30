# core/modules/web_scanner/csrf_check.py
import logging
import httpx

logger = logging.getLogger(__name__)


async def run_check(client: httpx.AsyncClient, base_url: str) -> dict | None:
    """
    Сканирует страницу безопасности/смены пароля на признаки отсутствия CSRF-защиты.
    """
    target_url = f"{base_url}/vulnerabilities/csrf/"

    try:
        response = await client.get(target_url, timeout=3.0)
        if response.status_code != 200:
            return None

        html_content = response.text.lower()

        # Список классических паттернов Anti-CSRF токенов
        csrf_signals = ["user_token", "csrf_token", "xsrf", "authenticity_token"]
        protected = any(token in html_content for token in csrf_signals)

        if not protected:
            return {
                "url": target_url,
                "vuln_type": "CSRF (Cross-Site Request Forgery)",
                "severity": "MEDIUM",
                "detail": "Форма изменения критических параметров пользователя не содержит Anti-CSRF токенов. Возможна подделка запроса.",
                "kb_id": "VULN-021"
            }
    except Exception as e:
        logger.error(f"Ошибка в плагине CSRF: {e}")

    return None