import asyncio
import logging
import ipaddress
from typing import List, Optional

from results import ScanResult
from banner import grab_http, grab_ssh, grab_ftp, grab_generic, check_tomcat_default_creds
from db_checker import check_redis, check_mongo, check_mysql_weak_creds, check_postgres_weak_creds, check_smb_ghost

logger = logging.getLogger(__name__)

# Расширенный список под Metasploitable 2
DEFAULT_PORTS = [
    21, 22, 23, 25, 53, 80, 111, 139, 443, 445, 512, 513, 514,
    1099, 1524, 2181, 3306, 3632, 5432, 5900, 6379, 27017, 8080, 8443, 2049,
    2121, 6000, 6667, 6697, 8009, 8180, 8787
]


async def _identify_service(host: str, port: int) -> tuple[str, Optional[str]]:
    """Определяет сервис и запускает активные пробники безопасности на основе порта."""
    try:
        if port in [80, 443, 8080, 8443]:
            banner = await grab_http(host, port)
            return "http", banner

        elif port in [21, 2121]:
            banner = await grab_ftp(host, port)
            return "ftp", banner

        elif port == 22:
            banner = await grab_ssh(host, port)
            return "ssh", banner

        elif port == 8180:
            # Специфичный порт Tomcat для Metasploitable 2
            res = await check_tomcat_default_creds(host, port)
            if res.get("vulnerable"):
                return "http-tomcat", "VULNERABLE: дефолтные учётные данные tomcat:tomcat"
            return "http-tomcat", "open"

        elif port == 6379:
            res = await check_redis(host, port)
            if res.get("vulnerable"):
                return "redis", "VULNERABLE: доступ без аутентификации"
            return "redis", "auth_required" if res.get("auth") else "open"

        elif port == 27017:
            res = await check_mongo(host, port)
            if res.get("vulnerable"):
                return "mongodb", "VULNERABLE: доступ без аутентификации"
            return "mongodb", "auth_required" if res.get("auth") else "open"

        elif port == 3306:
            res = await check_mysql_weak_creds(host, port)
            if res.get("vulnerable"):
                return "mysql", f"VULNERABLE: обнаружены слабые учётные данные ({res.get('detail')})"
            return "mysql", "open"

        elif port == 5432:
            # Наш новый активный пробник для PostgreSQL
            res = await check_postgres_weak_creds(host, port)
            if res.get("vulnerable"):
                return "postgresql", f"VULNERABLE: обнаружены слабые учётные данные ({res.get('detail')})"
            return "postgresql", "open"

        elif port == 445:
            # Наш новый активный пробник для SMB / Samba
            res = await check_smb_ghost(host, port)
            if res.get("vulnerable"):
                return "smb", f"VULNERABLE: {res.get('detail')} | Banner: {res.get('banner')}"
            return "smb", "open"

        else:
            # Для всех остальных портов собираем стандартный текстовый баннер
            banner = await grab_generic(host, port)
            return "unknown", banner

    except Exception as e:
        logger.debug(f"Ошибка идентификации сервиса на {host}:{port} -> {e}")
        return "unknown", None


async def scan_port(host: str, port: int, semaphore: asyncio.Semaphore, timeout: float = 2.0) -> ScanResult:
    """Асинхронно сканирует один порт хоста с использованием семафора конкурентности."""
    async with semaphore:
        status = "closed"
        service = "unknown"
        banner = None

        try:
            # Первичная проверка: открыт ли сокет в принципе
            _, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port),
                timeout=timeout
            )
            writer.close()
            await writer.wait_closed()
            status = "open"
        except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
            status = "closed"

        # Если порт открыт, запускаем глубокую идентификацию и активные чекеры
        if status == "open":
            service, banner = await _identify_service(host, port)

        return ScanResult(host=host, port=port, status=status, service=service, banner=banner)


async def scan_ports(target: str, ports: Optional[List[int]] = None, max_concurrency: int = 100) -> List[ScanResult]:
    """
    Сканирует список портов на цели (поддерживает как одиночный IP/домен, так и CIDR подсети).
    """
    ports = ports or DEFAULT_PORTS

    try:
        if "/" in target:
            network = ipaddress.ip_network(target, strict=False)
            hosts = [str(ip) for ip in network.hosts()]
        else:
            hosts = [target]
    except ValueError as e:
        logger.error(f"Некорректный целевой адрес или диапазон сети: {target} -> {e}")
        return []

    semaphore = asyncio.Semaphore(max_concurrency)
    tasks = [scan_port(host, port, semaphore) for host in hosts for port in ports]

    logger.info(f"Запуск сканирования сети для {target}. Всего задач: {len(tasks)}")
    results = await asyncio.gather(*tasks)
    return results