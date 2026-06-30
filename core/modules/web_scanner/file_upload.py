import logging
from typing import Optional

import httpx

from core.modules.web_scanner.types import WebCheck, WebFinding

logger = logging.getLogger(__name__)

CHECK_NAME = "File Upload"
TARGET_PATH = "/vulnerabilities/upload/"
REQUEST_TIMEOUT = 3.0
UPLOAD_FILENAME = "perimeter_shell.php"
UPLOAD_MARKERS = ("successfully uploaded", UPLOAD_FILENAME)


async def run_check(client: httpx.AsyncClient, base_url: str) -> Optional[WebFinding]:
    """
    Тестирует механизм валидации расширений файлов при загрузке.
    """
    target_url = f"{base_url}{TARGET_PATH}"

    # Имитируем отправку вредоносного PHP файла в памяти
    files = {
        "uploaded": (
            UPLOAD_FILENAME,
            b"<?php echo \"PERIMETER_VERIFIED\"; ?>",
            "application/x-php",
        )
    }
    data = {"Upload": "Upload"}

    try:
        response = await client.post(target_url, data=data, files=files, timeout=REQUEST_TIMEOUT)
        if response.status_code != 200:
            return None

        html_response = response.text.lower()

        # Проверяем маркеры успешной загрузки файла веб-сервером
        if any(marker in html_response for marker in UPLOAD_MARKERS):
            return WebFinding(
                url=target_url,
                vuln_type="Unrestricted File Upload",
                severity="CRITICAL",
                detail=(
                    "Форма загрузки принимает исполняемые PHP-файлы без проверки расширения или "
                    "MIME-типа. Риск полного захвата сервера (RCE)."
                ),
                kb_id="VULN-037",
            )
    except Exception as exc:
        logger.error("Ошибка в плагине File Upload: %s", exc)

    return None


CHECK = WebCheck(name=CHECK_NAME, run=run_check)
