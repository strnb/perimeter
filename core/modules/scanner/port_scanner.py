import asyncio
import logging
import ipaddress
from typing import List, Optional

# ИСПРАВЛЕННЫЕ ИМПОРТЫ: используем полные пути от корня проекта
from core.modules.scanner.results import ScanResult
from core.modules.scanner.banner import grab_http, grab_ssh, grab_ftp, grab_generic, check_tomcat_default_creds
from core.modules.scanner.db_checker import (
    check_redis, check_mongo, check_mysql_weak_creds,
    check_postgres_weak_creds, check_smb_ghost,
    check_telnet_banner, check_rpcbind, check_nfs,
    check_irc, check_distccd, check_bind_shell, check_vnc,
)

logger = logging.getLogger(__name__)

# Расширенный список под Metasploitable 2
DEFAULT_PORTS = [
    21, 22, 23, 25, 53, 80, 111, 139, 443, 445, 512, 513, 514,
    1099, 1524, 2181, 3306, 3632, 5432, 5900, 6379, 27017, 8080, 8443, 2049,
    2121, 6000, 6667, 6697, 8009, 8180, 8787, 6200
]

# Защита от опечатки в CIDR: больше этого числа проверок — отказ до первых пакетов
MAX_TASKS = 65_536


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

        if port == 23:
            res = await check_telnet_banner(host, port)
            banner = f"VULNERABLE: {res.get('banner', 'Telnet open')}" if res.get("vulnerable") else res.get("banner")
            return "telnet", banner

        if port == 111:
            res = await check_rpcbind(host, port)
            banner = f"VULNERABLE: {res.get('banner')}" if res.get("vulnerable") else res.get("banner", "rpcbind open")
            return "rpcbind", banner

        if port == 2049:
            res = await check_nfs(host, port)
            banner = f"VULNERABLE: {res.get('banner')}" if res.get("vulnerable") else res.get("banner", "NFS open")
            return "nfs", banner

        if port == 3632:
            res = await check_distccd(host, port)
            banner = f"VULNERABLE: {res.get('detail', res.get('banner', 'distccd open'))}"
            return "distccd", banner

        if port in (6667, 6697):
            res = await check_irc(host, port)
            banner = f"VULNERABLE: {res.get('detail', res.get('banner'))}" if res.get("vulnerable") else res.get("detail", "IRC handshake completed")
            return "irc", banner

        if port == 1524:
            res = await check_bind_shell(host, port)
            banner = f"VULNERABLE: {res.get('banner', 'root bind shell')}" if res.get("vulnerable") else f"Ingreslock open ({res.get('banner', '')})"
            return "ingreslock-backdoor", banner

        if port == 6200:
            res = await check_bind_shell(host, port)
            banner = f"VULNERABLE: vsFTPd backdoor shell ({res.get('banner', '')})" if res.get("vulnerable") else "port open, no shell"
            return "vsftpd-backdoor", banner

        if port == 5900:
            res = await check_vnc(host, port)
            banner = res.get("banner", "VNC open")
            return "vnc", banner

        elif port == 8180:
            # Специфичный порт Tomcat для Metasploitable 2
            res = await check_tomcat_default_creds(host, port)
            if res.get("weak_creds"):
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
            if res.get("status") == "error":
                return "mongodb", f"open (проверка слабых паролей недоступна: {res.get('reason')})"
            return "mongodb", "auth_required" if res.get("auth") else "open"

        elif port == 3306:
            res = await check_mysql_weak_creds(host, port)
            if res.get("vulnerable"):
                return "mysql", f"VULNERABLE: обнаружены слабые учётные данные ({res.get('detail')})"
            if res.get("status") == "error":
                return "mysql", f"open (проверка слабых паролей недоступна: {res.get('reason')})"
            return "mysql", "open"

        elif port == 5432:
            # Наш новый активный пробник для PostgreSQL
            res = await check_postgres_weak_creds(host, port)
            if res.get("vulnerable"):
                return "postgresql", f"VULNERABLE: обнаружены слабые учётные данные ({res.get('detail')})"
            if res.get("status") == "error":
                return "postgresql", f"open (проверка слабых паролей недоступна: {res.get('reason')})"
            return "postgresql", "open"

        elif port in (445,139):
            # Пробник подтверждает только протокол SMB, а не уязвимость
            res = await check_smb_ghost(host, port)
            if res.get("smb_confirmed"):
                return "smb", f"SMB Negotiate: {res.get('detail', '')[:100]}"
            return "smb", "open"

        else:
            # Для всех остальных портов собираем стандартный текстовый баннер
            banner = await grab_generic(host, port)
            return "unknown", banner

    except Exception as e:
        logger.debug(f"Ошибка идентификации сервиса на {host}:{port} -> {e}")
        return "unknown", None


async def scan_port(host: str, port: int, semaphore: asyncio.Semaphore, timeout: float = 1.0) -> ScanResult:
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

    # /8 × 65535 портов = сотни миллионов задач: проверяем до создания списков
    total = len(hosts) * len(ports)
    if total > MAX_TASKS:
        raise ValueError(
            f"Слишком большой объём скана: {len(hosts)} хостов × {len(ports)} портов "
            f"= {total} проверок (лимит {MAX_TASKS}). Сузьте CIDR или список портов."
        )

    semaphore = asyncio.Semaphore(max_concurrency)
    tasks = [scan_port(host, port, semaphore) for host in hosts for port in ports]

    logger.info(f"Запуск сканирования сети для {target}. Всего задач: {len(tasks)}")
    results = await asyncio.gather(*tasks) if tasks else []
    return [r for r in results if r.status == "open"]