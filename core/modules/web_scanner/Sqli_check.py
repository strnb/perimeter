import logging
from typing import Optional

import httpx

from core.modules.web_scanner.types import WebCheck, WebFinding

logger = logging.getLogger(__name__)

CHECK_NAME = "SQL Injection"
REQUEST_TIMEOUT = 3.0

# Классические error-based SQLi payloads
PAYLOADS = [
    "1'",
    "1 OR 1=1",
    "' OR '1'='1",
]

# Сигнатуры SQL-ошибок в ответе сервера
ERROR_SIGNATURES = [
    "sql syntax",
    "mysql_fetch",
    "unclosed quotation",
    "quoted string not properly terminated",
    "you have an error in your sql",
    "warning: mysql",
    "sqlstate",
    "pg_query",
    "sqlite3",
    "ora-",
    "syntax error",
]

# Сигнатуры успешного error-free SQLi (1=1 даёт больше записей чем 1=2)
BLIND_SIGNATURES = [
    "first name",   # DVWA показывает "First name: admin, Surname: admin" при успехе
    "surname",
]


async def _check_url(
    client: httpx.AsyncClient,
    url: str,
    param: str,
    payload: str,
) -> Optional[str]:
    """Один запрос с payload, возвращает тело ответа или None."""
    try:
        resp = await client.get(url, params={param: payload}, timeout=REQUEST_TIMEOUT)
        if resp.status_code == 200:
            return resp.text.lower()
    except Exception:
        pass
    return None


async def run_check(client: httpx.AsyncClient, base_url: str) -> Optional[WebFinding]:
    """
    Error-based SQLi: ищем SQL-ошибки в ответе при инъекции кавычки.
    Также проверяем boolean-based: 1=1 даёт результаты, 1=2 — нет.
    Путь и параметр — для DVWA. Через конфиг расширяется на другие сайты.
    """
    target_url = f"{base_url}/vulnerabilities/sqli/"
    param = "id"

    for payload in PAYLOADS:
        body = await _check_url(client, target_url, param, payload)
        if body is None:
            continue

        # Error-based
        for sig in ERROR_SIGNATURES:
            if sig in body:
                return WebFinding(
                    url=f"{target_url}?{param}={payload}",
                    vuln_type="SQL Injection (Error-based)",
                    severity="CRITICAL",
                    detail=(
                        f"Параметр '{param}' уязвим к SQL-инъекции. "
                        f"Payload '{payload}' вызвал SQL-ошибку в ответе. "
                        "Возможно чтение, изменение или удаление данных из БД."
                    ),
                    kb_id="VULN-039",
                )

        # Boolean-based: при 1 OR 1=1 должны быть данные
        for sig in BLIND_SIGNATURES:
            if sig in body:
                # Проверяем что 1=2 (всегда false) ничего не даёт
                false_body = await _check_url(client, target_url, param, "1 AND 1=2")
                if false_body and sig not in false_body:
                    return WebFinding(
                        url=f"{target_url}?{param}={payload}",
                        vuln_type="SQL Injection (Boolean-based Blind)",
                        severity="CRITICAL",
                        detail=(
                            f"Параметр '{param}' уязвим к boolean-based blind SQLi. "
                            f"Запрос '{payload}' вернул данные, тогда как 1=2 — нет. "
                            "Возможна полная выгрузка БД через последовательные запросы."
                        ),
                        kb_id="VULN-039",
                    )

    return None


CHECK = WebCheck(name=CHECK_NAME, run=run_check)