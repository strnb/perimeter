"""
pipeline.py
Связывает OSINT-модуль (osint.py) и сетевой сканер (port_scanner.py) в один
сквозной сценарий: домен -> поддомены/IP -> автоматический скан портов ->
обогащение находками (vuln_signatures.py).

Это и есть та самая "одна точка входа", о которой шла речь:
пользователь даёт домен, на выходе — готовый отчёт, без необходимости
самому дёргать 3 разных модуля и сводить результаты руками.
"""
import asyncio
import logging
from typing import Dict, List, Optional, Set

from .osint import run_osint, OSINTReport
from .port_scanner import scan_ports
from .results import ScanResult
from .vuln_signatures import match_vulnerabilities, VulnFinding

logger = logging.getLogger(__name__)


def _collect_targets(osint_report: OSINTReport, domain: str) -> Dict[str, Set[str]]:
    """
    Собирает уникальные IP из отчёта OSINT (поддомены + сам корневой домен)
    и для каждого IP — множество имён, которые на него резолвятся.
    Дедупликация важна: разные поддомены часто смотрят на один и тот же IP
    (особенно на shared hosting/CDN) — сканировать его несколько раз бессмысленно.
    """
    targets: Dict[str, Set[str]] = {}

    for sub in osint_report.get("subdomains", []):
        ip = sub.get("ip")
        name = sub.get("subdomain")
        if ip:
            targets.setdefault(ip, set()).add(name)

    for ip in osint_report.get("dns", {}).get("A", []):
        targets.setdefault(ip, set()).add(domain)

    return targets


async def osint_and_scan(
    domain: str,
    wordlist_path: str = "core/subdomains_wordlist.txt",
    ports: Optional[List[int]] = None,
    host_concurrency: int = 10,
    enrich: bool = True,
) -> dict:
    """
    Полный пайплайн: OSINT по домену -> скан портов на всех живых хостах ->
    (опционально) обогащение находками из vuln_signatures.

    Возвращает единый словарь:
    {
        "domain": ...,
        "osint": <полный OSINTReport>,
        "targets": {ip: [имена, которые на него резолвятся]},
        "scan_results": {ip: [ScanResult, ...]},
        "findings": [VulnFinding, ...]   # только если enrich=True
    }
    """
    logger.info(f"[pipeline] Запуск OSINT для {domain}")
    osint_report = await run_osint(domain, wordlist_path)

    targets = _collect_targets(osint_report, domain)
    logger.info(f"[pipeline] Найдено {len(targets)} уникальных живых хостов для скана")

    sem = asyncio.Semaphore(host_concurrency)

    async def _scan_one(ip: str) -> tuple[str, List[ScanResult]]:
        async with sem:
            try:
                results = await scan_ports(ip, ports=ports)
                return ip, results
            except Exception as e:
                # Изоляция: один сбойный хост не должен ронять весь пайплайн
                logger.error(f"[pipeline] Скан {ip} провалился: {e}")
                return ip, []

    if targets:
        pairs = await asyncio.gather(*[_scan_one(ip) for ip in targets])
    else:
        pairs = []

    scan_results: Dict[str, List[ScanResult]] = {ip: results for ip, results in pairs}

    output = {
        "domain": domain,
        "osint": osint_report,
        "targets": {ip: sorted(names) for ip, names in targets.items()},
        "scan_results": scan_results,
    }

    if enrich:
        all_results: List[ScanResult] = [r for results in scan_results.values() for r in results]
        output["findings"] = match_vulnerabilities(all_results)
        logger.info(f"[pipeline] Найдено {len(output['findings'])} находок после обогащения")

    return output