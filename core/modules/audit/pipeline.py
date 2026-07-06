import asyncio
import logging
from typing import List

from core.modules.scanner.pipeline import osint_and_scan
from core.modules.web_scanner.web_pipeline import run_web_assessment

logger = logging.getLogger(__name__)

WEB_PORTS = {80, 443}


async def run_audit(
    domain: str,
    wordlist_path: str = "core/subdomains_wordlist.txt",
    ports: List[int] | None = None,
    host_concurrency: int = 10,
    enrich: bool = True,
) -> dict:

    logger.info("[Audit] Запуск аудита %s", domain)

    result = await osint_and_scan(
        domain=domain,
        wordlist_path=wordlist_path,
        ports=ports,
        host_concurrency=host_concurrency,
        enrich=enrich,
    )

    result["web_assessment"] = {}

    web_tasks = []
    web_hosts = []

    for ip, scans in result["scan_results"].items():

        for scan in scans:

            if scan.port in WEB_PORTS:

                logger.info(
                    "[Audit] Найден веб-сервис %s:%s",
                    ip,
                    scan.port,
                )

                web_hosts.append((ip, scan.port))

                web_tasks.append(
                    asyncio.create_task(
                        run_web_assessment(
                            target_ip=ip,
                            port=scan.port,
                        )
                    )
                )

                break

    if web_tasks:

        responses = await asyncio.gather(
            *web_tasks,
            return_exceptions=True,
        )

        for (ip, port), response in zip(web_hosts, responses):

            if isinstance(response, Exception):

                logger.exception(
                    "[Audit] Ошибка Web Scanner %s:%s",
                    ip,
                    port,
                )

                result["web_assessment"][ip] = {
                    "host": ip,
                    "port": port,
                    "protocol": "https" if port == 443 else "http",
                    "error": str(response),
                }

            else:

                result["web_assessment"][ip] = {
                    "host": ip,
                    "port": port,
                    "protocol": "https" if port == 443 else "http",
                    "findings": response,
                }

    else:

        logger.info("[Audit] Веб-сервисы не найдены")

    logger.info("[Audit] Аудит завершён")

    return result