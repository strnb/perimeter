# core/modules/web_scanner/xss_check.py
import logging
import httpx

logger = logging.getLogger(__name__)


async def run_check(client: httpx.AsyncClient, base_url: str) -> dict | None:
    """
    Тестирует веб-приложение на наличие уязвимости Reflected XSS.
    """
    target_url = f"{base_url}/vulnerabilities/xss_r/"
    # Безопасный payload, содержащий спецсимволы, которые должны экранироваться
    payload = "PerimeterXSS'\"<>"

    try:
        response = await client.get(target_url, params={"name": payload}, timeout=3.0)
        if response.status_code != 200:
            return None

        # Если сервер возвращает спецсимволы без санитизации (не превратил < > в &lt; &gt;)
        if payload in response.text:
            return {
                "url": target_url,
                "vuln_type": "Reflected XSS",
                "severity": "HIGH",
                "detail": f"Входные данные отражаются сервером без должной фильтрации. Браузер может выполнить произвольный JS-код. Payload: {payload}",
                "kb_id": "VULN-022"
            }
    except Exception as e:
        logger.error(f"Ошибка в плагине XSS: {e}")

    return None