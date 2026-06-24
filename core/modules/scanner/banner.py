import asyncio
import re
import ssl
import logging

HTTP_SERVER_REGEX = re.compile(r"Server:\s*(.+)", re.IGNORECASE)

async def grab_http(host: str, port: int, timeout: float = 2.0) -> str:
    """HTTP/HTTPS граббер с поддержкой альтернативных портов (443, 8443)."""
    payload = "GET / HTTP/1.0\r\nHost: {}\r\n\r\n".format(host).encode('utf-8')
    try:
        ssl_context = None
        # Чиню баг: проверяем оба SSL-порта
        if port in [443, 8443]:
            ssl_context = ssl.create_default_context()
            ssl_context.check_hostname = False
            ssl_context.verify_mode = ssl.CERT_NONE

        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port, ssl=ssl_context),
            timeout=timeout
        )
        writer.write(payload)
        await writer.drain()

        data = await reader.read(1024)
        writer.close()
        await writer.wait_closed()

        response_text = data.decode('utf-8', errors='ignore')
        match = HTTP_SERVER_REGEX.search(response_text)
        return match.group(1).strip() if match else "unknown"
    except Exception:
        return "unknown"

async def grab_ssh(host: str, port: int = 22, timeout: float = 2.0) -> str:
    try:
        reader, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=timeout)
        data = await reader.read(256)
        writer.close()
        await writer.wait_closed()
        return data.decode('utf-8', errors='ignore').strip()
    except Exception:
        return "unknown"

async def grab_ftp(host: str, port: int = 21, timeout: float = 2.0) -> str:
    try:
        reader, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=timeout)
        data = await reader.read(512)
        writer.close()
        await writer.wait_closed()
        banner = data.decode('utf-8', errors='ignore').strip()
        return banner[3:].strip() if banner.startswith("220") else banner
    except Exception:
        return "unknown"

async def grab_generic(host: str, port: int, timeout: float = 2.0) -> str:
    """Generic-граббер для портов, которые сами плюются баннером (SMTP, Telnet и т.д.)."""
    try:
        reader, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=timeout)
        data = await reader.read(512)
        writer.close()
        await writer.wait_closed()
        banner = data.decode('utf-8', errors='ignore').strip()
        return banner if banner else "raw open"
    except Exception:
        return "unknown"