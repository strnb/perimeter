import asyncio
import logging
import ipaddress
import time
from modules.scanner.results import ScanResult
from modules.scanner.banner import grab_http, grab_ssh, grab_ftp
from modules.scanner.db_checker import check_redis, check_mongo

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

DEFAULT_PORTS = [21, 22, 23, 80, 443, 2181, 3306, 5432, 6379, 27017, 8080, 8443]


async def scan_port(host: str, port: int, semaphore: asyncio.Semaphore, timeout: float = 1.0) -> ScanResult:
    """
    Сканирует порт, собирает баннеры или проверяет СУБД на уязвимости (без пароля).
    """
    async with semaphore:
        status = "closed"
        banner = None
        service = "unknown"

        try:
            # 1. Быстрая проверка сетевой доступности порта
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port),
                timeout=timeout
            )
            writer.close()
            await writer.wait_closed()
            status = "open"

            # 2. Интеграция Banner Grabbing (Задачи 6-8)
            if port in [80, 443, 8080, 8443]:
                service = "http" if port != 443 and port != 8443 else "https"
                banner = await grab_http(host, port)
            elif port == 22:
                service = "ssh"
                banner = await grab_ssh(host, port)
            elif port == 21:
                service = "ftp"
                banner = await grab_ftp(host, port)

            # 3. Интеграция Детекторов СУБД (Задачи 9-13)
            elif port == 6379:
                service = "redis"
                redis_info = await check_redis(host, port)
                if redis_info.get("status") == "open":
                    banner = "Auth Required" if redis_info.get("auth") else "VULNERABLE: No Auth (+PONG)"
            elif port == 27017:
                service = "mongodb"
                mongo_info = await check_mongo(host, port)
                if mongo_info.get("status") == "open":
                    banner = "Auth Required" if mongo_info.get("auth") else "VULNERABLE: No Auth"
                elif mongo_info.get("status") == "error":
                    banner = "Scanner error: pymongo missing"

        except asyncio.TimeoutError:
            status = "timeout"
        except (ConnectionRefusedError, OSError):
            status = "closed"

        return ScanResult(host=host, port=port, status=status, service=service, banner=banner)


async def scan_ports(target: str, ports: list[int] = None, max_concurrency: int = 100) -> list[ScanResult]:
    """
    Сканирует цель (IP/CIDR) и возвращает только открытые порты с полной ИБ-разведкой.
    """
    if ports is None:
        ports = DEFAULT_PORTS

    if "/" in target:
        hosts_to_scan = expand_cidr(target)
    else:
        hosts_to_scan = [target]

    sem = asyncio.Semaphore(max_concurrency)
    tasks = []

    for host in hosts_to_scan:
        for port in ports:
            tasks.append(scan_port(host, port, semaphore=sem))

    all_results = await asyncio.gather(*tasks)
    return [res for res in all_results if res.status == "open"]


def expand_cidr(cidr: str) -> list[str]:
    try:
        network = ipaddress.ip_network(cidr, strict=False)
        return [str(ip) for ip in network.hosts()]
    except ValueError:
        return []