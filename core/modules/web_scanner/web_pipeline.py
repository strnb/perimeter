"""
web_pipeline.py

Главная точка входа Web Scanner.

Pipeline:
    1. (опционально) Логин на таргет по конфигу профиля (config.py)
    2. Запуск всех активных проверок из registry.py
    3. Определение технологий (tech_detector.py)
    4. Проверка security-заголовков (headers_checker.py)
    5. Сборка единого результата
"""

import asyncio
import logging
import re
from typing import Dict, Iterable, List, Optional

import httpx

from core.modules.web_scanner.registry import CHECKS
from core.modules.web_scanner.tech_detector import detect_technologies
from core.modules.web_scanner.headers_checker import check_headers
from core.modules.web_scanner.types import WebFinding
from core.modules.web_scanner.config import ACTIVE_PROFILE, WebTarget

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Запуск проверок из registry.py
# ---------------------------------------------------------------------------

async def _run_checks(
    client: httpx.AsyncClient,
    base_url: str,
) -> List[WebFinding]:
    """
    Запускает все проверки из registry.py.
    """

    tasks = [
        check.run(client, base_url)
        for check in CHECKS
    ]

    results = await asyncio.gather(
        *tasks,
        return_exceptions=True,
    )

    findings: List[WebFinding] = []

    for check, result in zip(CHECKS, results):

        if isinstance(result, Exception):

            logger.error(
                "[Web Scanner] %s: %s",
                check.name,
                result,
            )

            continue

        if isinstance(result, WebFinding):
            findings.append(result)

    return findings


def _serialize_findings(
    findings: Iterable[WebFinding],
) -> List[Dict]:
    """
    Преобразует WebFinding в словарь.
    """

    return [
        finding.as_dict()
        for finding in findings
    ]


# ---------------------------------------------------------------------------
# Универсальный логин (DVWA + произвольные реальные сайты)
# ---------------------------------------------------------------------------

async def _perform_login(
    client: httpx.AsyncClient,
    base_url: str,
    profile: WebTarget,
) -> bool:
    """
    Универсальный логин по конфигу профиля.
    Работает и для DVWA, и для произвольного реального сайта —
    вся специфика вынесена в config.py, а не в код.

    Возвращает True, если авторизация прошла (или не требовалась —
    в этом случае поведение сканера не меняется, просто сканируем
    неавторизованно).
    """
    if not profile.login_path or not profile.username or not profile.password:
        logger.info(
            "[Web Scanner] Креды не заданы для профиля '%s' — сканируем неавторизованно",
            profile.name,
        )
        return False

    login_url = f"{base_url}{profile.login_path}"

    try:
        # 1. Забираем страницу логина и вытаскиваем ВСЕ hidden-поля формы
        #    (CSRF-токены у разных сайтов называются по-разному: user_token,
        #    csrf_token, _token, authenticity_token и т.д. — не хардкодим имя).
        get_resp = await client.get(login_url, timeout=10)

        hidden_fields = dict(re.findall(
            r"<input[^>]*type=[\"']hidden[\"'][^>]*name=[\"']([^\"']+)[\"'][^>]*value=[\"']([^\"']*)[\"']",
            get_resp.text, re.I,
        ))
        if not hidden_fields:
            # некоторые формы пишут атрибуты в другом порядке: value перед name
            hidden_fields = dict(re.findall(
                r"<input[^>]*name=[\"']([^\"']+)[\"'][^>]*type=[\"']hidden[\"'][^>]*value=[\"']([^\"']*)[\"']",
                get_resp.text, re.I,
            ))

        # 2. Собираем данные формы: hidden-поля + креды + submit-кнопка (если есть)
        data = {
            **hidden_fields,
            profile.login_user_param: profile.username,
            profile.login_pass_param: profile.password,
        }
        if profile.login_submit_param:
            data[profile.login_submit_param] = "Login"

        login_resp = await client.post(
            login_url, data=data, follow_redirects=True, timeout=10,
        )

        # 3. Проверяем успех
        if profile.login_success_marker:
            success = profile.login_success_marker.lower() in login_resp.text.lower()
        else:
            # Эвристика: если поля логина/пароля больше не встречаются в ответе —
            # скорее всего, форма логина исчезла, значит мы вошли.
            success = (
                profile.login_user_param not in login_resp.text
                and profile.login_pass_param not in login_resp.text
            )

        if not success:
            logger.warning(
                "[Web Scanner] Логин в '%s' не подтверждён — работаем неавторизованно",
                profile.name,
            )
            return False

        # 4. Доп. шаг после логина (специфика конкретного таргета, напр. DVWA security level)
        if profile.post_login_path:
            await client.get(f"{base_url}{profile.post_login_path}", timeout=10)
            if profile.post_login_data:
                await client.post(
                    f"{base_url}{profile.post_login_path}",
                    data=profile.post_login_data,
                    timeout=10,
                )

        logger.info("[Web Scanner] Успешный вход в '%s'", profile.name)
        return True

    except Exception as exc:
        logger.error("[Web Scanner] Ошибка логина ('%s'): %s", profile.name, exc)
        return False


# ---------------------------------------------------------------------------
# Главная точка входа
# ---------------------------------------------------------------------------

async def run_web_assessment(
    target_ip: str,
    port: int,
    cookies: Optional[Dict[str, str]] = None,
) -> dict:
    """
    Главная точка входа Web Scanner.

    Returns
    -------
    dict с ключами:
        host, port, protocol, authenticated,
        findings (list[dict]), technologies (list[str]), headers (list[dict])
    """

    scheme = "https" if port == 443 else "http"

    base_url = f"{scheme}://{target_ip}:{port}"

    async with httpx.AsyncClient(
        cookies=cookies,
        follow_redirects=False,
        verify=False,
        timeout=15,
    ) as client:

        logger.info(
            "[Web Scanner] Проверка %s",
            base_url,
        )

        # Если снаружи уже передали cookies (например, вручную залогинились
        # в реальном сайте и достали сессию) — не логинимся повторно.
        authenticated = bool(cookies)
        if not authenticated:
            authenticated = await _perform_login(client, base_url, ACTIVE_PROFILE)

        findings = await _run_checks(
            client,
            base_url,
        )

    #
    # Дополнительные проверки (отдельные короткоживущие клиенты внутри)
    #

    technologies = await detect_technologies(
        target_ip,
        port,
    )

    headers = await check_headers(
        target_ip,
        port,
    )

    return {
        "host": target_ip,
        "port": port,
        "protocol": scheme,
        "authenticated": authenticated,
        "findings": _serialize_findings(findings),
        "technologies": technologies,
        "headers": headers,
    }
