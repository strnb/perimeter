# core/modules/web_scanner/checkers/brute_force.py
import asyncio
import httpx
import logging

logger = logging.getLogger(__name__)


async def run_check(client: httpx.AsyncClient, base_url: str) -> dict | None:
    """
    Проверяет отсутствие блокировки аккаунта (Rate Limiting) и капчи в DVWA.
    """
    target_url = f"{base_url}/vulnerabilities/brute/"
    tasks = []

    # Генерируем 10 быстрых параллельных запросов авторизации
    for i in range(10):
        params = {"username": "admin", "password": f"fake_pass_{i}", "Login": "Login"}
        tasks.append(client.get(target_url, params=params, timeout=2.0))

    try:
        responses = await asyncio.gather(*tasks, return_exceptions=True)
        success_count = sum(1 for r in responses if isinstance(r, httpx.Response) and r.status_code == 200)

        # Если веб-сервер успешно вернул страницу для всех 10 попыток без задержек и капчи
        if success_count == 10:
            return {
                "url": target_url,
                "vuln_type": "Brute Force / No Rate Limiting",
                "severity": "HIGH",
                "detail": "Веб-форма авторизации не блокирует сессию и не активирует CAPTCHA при атаке методом перебора.",
                "kb_id": "VULN-020"
            }
    except Exception as e:
        logger.error(f"Ошибка в плагине Brute Force: {e}")

    return None