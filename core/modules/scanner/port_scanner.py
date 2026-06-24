import asyncio
import logging
import ipaddress
import time
from modules.scanner.results import ScanResult
from modules.scanner.banner import grab_http, grab_ssh, grab_ftp, grab_generic
from modules.scanner.db_checker import check_redis, check_mongo

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

# Расширенный список под Metasploitable 2
DEFAULT_PORTS = [
    21, 22, 23, 25, 53, 80, 111, 139, 443, 445, 512, 513, 514,
    1099, 1524, 2181, 3306, 3632, 5432, 5900, 6379, 27017, 8080, 8443
]


async def scan_port(host: str, port: int, semaphore: asyncio.Semaphore, timeout: float = 1.0) -> ScanResult:
    """Сканирует порт с жесткой изоляцией ошибок парсинга и плагинов."""
    async with semaphore:
        status = "closed"
        banner = None
        service = "unknown"

        # Шаг 1: Сетевой коннект
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port),
                timeout=timeout
            )
            writer.close()
            await writer.wait_closed()
            status = "open"
        except asyncio.TimeoutError:
            status = "timeout"
        except (ConnectionRefusedError, OSError):
            status = "closed"

        # Шаг 2: Изолированная разведка (если порт открыт, падение плагина не должно валить скан)
        if status == "open":
            try:
                if port in [80, 443, 8080, 8443]:
                    service = "http" if port not in [443, 8443] else "https"
                    banner = await grab_http(host, port)
                elif port == 22:
                    service = "ssh"
                    banner = await grab_ssh(host, port)
                elif port == 21:
                    service = "ftp"
                    banner = await grab_ftp(host, port)
                elif port == 6379:
                    service = "redis"
                    redis_info = await check_redis(host, port)
                    banner = "Auth Required" if redis_info.get("auth") else "VULNERABLE: No Auth (+PONG)"
                elif port == 27017:
                    service = "mongodb"
                    mongo_info = await check_mongo(host, port)
                    # Если Mongo-чекер вернул ошибку или None (перестраховка)
                    if mongo_info and mongo_info.get("status") == "open":
                        banner = "Auth Required" if mongo_info.get("auth") else "VULNERABLE: No Auth"
                    else:
                        banner = "Mongo open (auth status unknown)"
                else:
                    # Fallback на generic-граббер для всех остальных портов Metasploitable
                    service = "detected"
                    banner = await grab_generic(host, port)
            except Exception as e:
                # Перехватываем вообще всё (AttributeError, KeyError и т.д.), защищая gather
                logging.error(f"[-] Бакенд-ошибка плагина на {host}:{port} -> {e}")
                banner = f"Scan error inside module"

        return ScanResult(host=host, port=port, status=status, service=service, banner=banner)


async def scan_ports(target: str, ports: list[int] = None, max_concurrency: int = 100) -> list[ScanResult]:
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