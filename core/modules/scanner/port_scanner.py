import asyncio
import logging
import ipaddress
from typing import List, Optional

# Исправленные импорты для соответствия структуре проекта
from core.modules.scanner.results import ScanResult
from core.modules.scanner.banner import grab_http, grab_ssh, grab_ftp, grab_generic
from core.modules.scanner.db_checker import check_redis, check_mongodb

logger = logging.getLogger(__name__)

# Расширенный список под Metasploitable 2
DEFAULT_PORTS = [
    21, 22, 23, 25, 53, 80, 111, 139, 443, 445, 512, 513, 514,
    1099, 1524, 2181, 3306, 3632, 5432, 5900, 6379, 27017, 8080, 8443
]

async def _identify_service(host: str, port: int) -> tuple[str, Optional[str]]:
    """Определяет сервис и получает баннер на основе порта."""
    try:
        if port in [80, 443, 8080, 8443]:
            service = "http" if port not in [443, 8443] else "https"
            banner = await grab_http(host, port)
            return service, banner
            
        if port == 22:
            return "ssh", await grab_ssh(host, port)
            
        if port == 21:
            return "ftp", await grab_ftp(host, port)
            
        if port == 6379:
            res = await check_redis(host, port)
            banner = "Auth Required" if res.get("auth") else "VULNERABLE: No Auth (+PONG)"
            return "redis", banner
            
        if port == 27017:
            res = await check_mongodb(host, port)
            if res.get("status") == "open":
                banner = "Auth Required" if res.get("auth") else "VULNERABLE: No Auth"
            else:
                banner = f"Mongo status: {res.get('status')} ({res.get('reason')})"
            return "mongodb", banner

        # Fallback для остальных портов
        return "detected", await grab_generic(host, port)
        
    except Exception as e:
        logger.error(f"Plugin error for {host}:{port} -> {e}")
        return "error", f"Scan error: {str(e)}"

async def scan_port(host: str, port: int, semaphore: asyncio.Semaphore, timeout: float = 1.0) -> ScanResult:
    """Сканирует один порт с изоляцией ошибок."""
    async with semaphore:
        status = "closed"
        service = "unknown"
        banner = None

        # Шаг 1: Сетевой коннект
        try:
            _, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port),
                timeout=timeout
            )
            writer.close()
            await writer.wait_closed()
            status = "open"
        except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
            status = "closed"

        # Шаг 2: Идентификация сервиса
        if status == "open":
            service, banner = await _identify_service(host, port)

        return ScanResult(host=host, port=port, status=status, service=service, banner=banner)

async def scan_ports(target: str, ports: Optional[List[int]] = None, max_concurrency: int = 100) -> List[ScanResult]:
    """Сканирует список портов на цели (IP или CIDR)."""
    ports = ports or DEFAULT_PORTS
    
    try:
        if "/" in target:
            network = ipaddress.ip_network(target, strict=False)
            hosts = [str(ip) for ip in network.hosts()]
        else:
            hosts = [target]
    except ValueError as e:
        logger.error(f"Invalid target: {target} -> {e}")
        return []

    semaphore = asyncio.Semaphore(max_concurrency)
    tasks = [scan_port(host, port, semaphore) for host in hosts for port in ports]
    
    logger.info(f"Starting scan for {len(hosts)} hosts, {len(ports)} ports each...")
    results = await asyncio.gather(*tasks)
    
    # Возвращаем только открытые порты
    return [res for res in results if res.status == "open"]
