import asyncio
import re
import ssl
import logging
from typing import Optional

# Настройка логгера
logger = logging.getLogger(__name__)

HTTP_SERVER_REGEX = re.compile(r"Server:\s*(.+)", re.IGNORECASE)

async def _safe_grab(
    host: str, 
    port: int, 
    payload: Optional[bytes] = None, 
    timeout: float = 2.0, 
    read_size: int = 1024,
    use_ssl: bool = False
) -> str:
    """Базовая функция для безопасного получения баннера из сокета."""
    reader, writer = None, None
    try:
        ssl_context = None
        if use_ssl:
            ssl_context = ssl.create_default_context()
            ssl_context.check_hostname = False
            ssl_context.verify_mode = ssl.CERT_NONE

        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port, ssl=ssl_context),
            timeout=timeout
        )

        if payload:
            writer.write(payload)
            await writer.drain()

        data = await reader.read(read_size)
        return data.decode('utf-8', errors='ignore').strip()
    except asyncio.TimeoutError:
        logger.debug(f"Timeout grabbing banner from {host}:{port}")
        return "timeout"
    except Exception as e:
        logger.debug(f"Error grabbing banner from {host}:{port}: {e}")
        return "unknown"
    finally:
        if writer:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass

async def grab_http(host: str, port: int, timeout: float = 2.0) -> str:
    """HTTP/HTTPS граббер."""
    payload = f"GET / HTTP/1.0\r\nHost: {host}\r\n\r\n".encode('utf-8')
    use_ssl = port in [443, 8443]
    
    response = await _safe_grab(host, port, payload=payload, timeout=timeout, use_ssl=use_ssl)
    
    if response in ["unknown", "timeout"]:
        return response
        
    match = HTTP_SERVER_REGEX.search(response)
    return match.group(1).strip() if match else "unknown"

async def grab_ssh(host: str, port: int = 22, timeout: float = 2.0) -> str:
    """SSH граббер."""
    return await _safe_grab(host, port, timeout=timeout, read_size=256)

async def grab_ftp(host: str, port: int = 21, timeout: float = 2.0) -> str:
    """FTP граббер."""
    banner = await _safe_grab(host, port, timeout=timeout, read_size=512)
    if banner.startswith("220"):
        return banner[3:].strip()
    return banner

async def grab_generic(host: str, port: int, timeout: float = 2.0) -> str:
    """Generic-граббер для SMTP, Telnet и других сервисов."""
    banner = await _safe_grab(host, port, timeout=timeout, read_size=512)
    if banner in ["unknown", "timeout"]:
        return banner
    return banner if banner else "raw open"
