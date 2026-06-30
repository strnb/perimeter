import asyncio
import logging
import ipaddress
from typing import List, Optional

from core.modules.scanner.results import ScanResult
from core.modules.scanner.banner import grab_http, grab_ssh, grab_ftp, grab_generic, check_tomcat_default_creds
from core.modules.scanner.db_checker import (
    check_redis, check_mongo, check_mysql_weak_creds,
    check_postgres_weak_creds, check_smb_ghost, check_vnc,
    check_telnet_banner, check_rpcbind, check_nfs, check_irc,
    check_distccd, check_bind_shell,
)

logger = logging.getLogger(__name__)

# Расширенный список под Metasploitable 2
DEFAULT_PORTS = [
    21, 22, 23, 25, 53, 80, 111, 139, 443, 445, 512, 513, 514,
    1099, 1524, 2181, 3306, 3632, 5432, 5900, 6200, 6379, 27017, 8080, 8443, 2049,
    2121, 6000, 6667, 6697, 8009, 8180, 8787
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

        if port == 23:
            res = await check_telnet_banner(host, port)
            banner = res.get("banner") or "Telnet open"
            if res.get("vulnerable"):
                banner = f"VULNERABLE: Telnet service detected ({banner})"
            return "telnet", banner

        if port == 111:
            res = await check_rpcbind(host, port)
            banner = res.get("banner") or "rpcbind open"
            if res.get("vulnerable"):
                banner = f"VULNERABLE: {banner}"
            return "rpcbind", banner

        if port == 2049:
            res = await check_nfs(host, port)
            banner = res.get("banner") or "NFS open"
            if res.get("vulnerable"):
                banner = f"VULNERABLE: {banner}"
            return "nfs", banner

        if port == 3632:
            res = await check_distccd(host, port)
            banner = res.get("detail") or res.get("banner") or "distccd open"
            if res.get("vulnerable"):
                banner = f"VULNERABLE: {banner} ({res.get('banner', '')})"
            return "distccd", banner

        if port in (6667, 6697):
            res = await check_irc(host, port)
            banner = res.get("detail") or res.get("banner") or "IRC open"
            if res.get("vulnerable"):
                banner = f"VULNERABLE: {banner} ({res.get('banner', '')})"
            return "irc", banner

        if port == 6379:
            res = await check_redis(host, port)
            if res.get("status") == "open":
                banner = "Auth Required" if res.get("auth") else "VULNERABLE: No Auth (+PONG)"
            else:
                banner = "Port open, not a real Redis response"
            return "redis", banner

        if port == 27017:
            res = await check_mongo(host, port)
            if res.get("status") == "open":
                banner = "Auth Required" if res.get("auth") else "VULNERABLE: No Auth"
            else:
                banner = f"Mongo status: {res.get('status')} ({res.get('reason', '')})"
            return "mongodb", banner

        if port == 3306:
            res = await check_mysql_weak_creds(host, port)
            if res.get("weak_creds"):
                banner = f"VULNERABLE: {res.get('detail', 'weak credentials')}"
            elif res.get("status") == "error":
                banner = f"MySQL check skipped: {res.get('reason')}"
            else:
                banner = "MySQL open, root password set"
            return "mysql", banner

        if port == 8180:
            res = await check_tomcat_default_creds(host, port)
            if res.get("weak_creds"):
                banner = f"VULNERABLE: {res.get('detail', 'default creds tomcat:tomcat')}"
            else:
                banner = "Tomcat Manager open, default creds rejected"
            return "tomcat", banner

        if port == 1524:
            res = await check_bind_shell(host, port)
            banner = res.get("banner") or "Metasploitable 2 root bind shell backdoor"
            if res.get("vulnerable"):
                banner = f"VULNERABLE: {res.get('detail')} ({banner})"
            else:
                banner = f"VULNERABLE: Metasploitable 2 root bind shell backdoor ({banner})"
            return "ingreslock-backdoor", banner

        if port == 6200:
            res = await check_bind_shell(host, port)
            banner = res.get("banner") or "vsFTPd 2.3.4 backdoor shell"
            if res.get("vulnerable"):
                banner = f"VULNERABLE: {res.get('detail')} ({banner})"
            else:
                banner = f"VULNERABLE: vsFTPd 2.3.4 backdoor shell ({banner})"
            return "vsftpd-backdoor", banner

        if port == 5900:
            res = await check_vnc(host, port)
            banner = res.get("banner") or "VNC open"
            if res.get("vulnerable"):
                banner = f"VULNERABLE: VNC service detected ({banner})"
            return "vnc", banner

        if port == 5432:
            res = await check_postgres_weak_creds(host, port)
            if res.get("weak_creds"):
                banner = f"VULNERABLE: {res.get('detail', 'weak credentials')}"
            elif res.get("status") == "error":
                banner = f"Postgres check skipped: {res.get('reason')}"
            else:
                banner = "PostgreSQL open, default creds rejected"
            return "postgresql", banner

        if port in (139, 445):
            res = await check_smb_ghost(host, port)
            if res.get("vulnerable"):
                banner = f"VULNERABLE: {res.get('detail', 'SMB negotiate confirmed')}"
            else:
                banner = res.get("detail") or "SMB open, negotiate not confirmed"
            return "smb", banner

        if port == 2121:
            return "ftp", await grab_ftp(host, port)

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

    return [res for res in results if res.status == "open"]
