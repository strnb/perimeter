# core/modules/web_scanner/file_upload.py
import logging
import httpx

logger = logging.getLogger(__name__)


async def run_check(client: httpx.AsyncClient, base_url: str) -> dict | None:
    """
    Тестирует механизм валидации расширений файлов при загрузке.
    """
    target_url = f"{base_url}/vulnerabilities/upload/"

    # Имитируем отправку вредоносного PHP файла в памяти
    files = {'uploaded': ('perimeter_shell.php', b'<?php echo "PERIMETER_VERIFIED"; ?>', 'application/x-php')}
    data = {'Upload': 'Upload'}

    try:
        response = await client.post(target_url, data=data, files=files, timeout=3.0)
        if response.status_code != 200:
            return None

        html_response = response.text.lower()

        # Проверяем маркеры успешной загрузки файла веб-сервером
        if "successfully uploaded" in html_response or "perimeter_shell.php" in html_response:
            return {
                "url": target_url,
                "vuln_type": "Unrestricted File Upload",
                "severity": "CRITICAL",
                "detail": "Форма загрузки принимает исполняемые PHP-файлы без проверки расширения или MIME-типа. Риск полного захвата сервера (RCE).",
                "kb_id": "VULN-023"
            }
    except Exception as e:
        logger.error(f"Ошибка в плагине File Upload: {e}")

    return None