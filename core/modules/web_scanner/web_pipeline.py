# core/modules/web_scanner/web_pipeline.py
import asyncio
import logging
from typing import List, Dict

import httpx

# Импортируем модули из этой же папки напрямую
from core.modules.web_scanner import (
    brute_force,
    csrf_check,
    xss_check,
    file_upload,
    open_redirect
)

logger = logging.getLogger(__name__)


async def run_web_assessment(target_ip: str, port: int = 4280, cookies: Dict[str, str] = None) -> List[Dict]:
    """
    Глобальная точка входа для аудита уязвимостей L7 (Web).
    Запускает все модули в параллельном асинхронном режиме.
    """
    base_url = f"http://{target_ip}:{port}"
    web_findings = []

    # Единый асинхронный клиент для оптимизации сессий
    async with httpx.AsyncClient(cookies=cookies, follow_redirects=False) as client:

        # Формируем задачи
        tasks = [
            brute_force.run_check(client, base_url),
            csrf_check.run_check(client, base_url),
            xss_check.run_check(client, base_url),
            file_upload.run_check(client, base_url),
            open_redirect.run_check(client, base_url)
        ]

        logger.info(f"[Web Scanner] Запуск 5 асинхронных веб-модулей для веб-сервера {base_url}")

        # Выполняем параллельно
        results = await asyncio.gather(*tasks, return_exceptions=True)

        # Агрегируем успешные срабатывания
        for res in results:
            if isinstance(res, dict):
                web_findings.append(res)
            elif isinstance(res, Exception):
                logger.error(f"[Web Scanner] Критическая ошибка выполнения модуля: {res}")

    return web_findings