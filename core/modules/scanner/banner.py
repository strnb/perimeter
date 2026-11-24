import asyncio
import re
import ssl
import base64
import logging

HTTP_SERVER_REGEX = re.compile(r"Server:\s*(.+)", re.IGNORECASE)

async def grab_http(host: str, port: int, timeout: float = 2.0) -> str:
    """HTTP/HTTPS граббер с поддержкой альтернативных портов (443, 8443)."""
    payload = "GET / HTTP/1.0\r\nHost: {}\r\n\r\n".format(host).encode('utf-8')
    try:
        ssl_context = None
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

        # ВАЖНО: read() сам по себе не имеет таймаута и может ждать вечно,
        # если сервер ничего не присылает в ответ — оборачиваем отдельно.
        data = await asyncio.wait_for(reader.read(1024), timeout=timeout)
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
        data = await asyncio.wait_for(reader.read(256), timeout=timeout)
        writer.close()
        await writer.wait_closed()
        return data.decode('utf-8', errors='ignore').strip()
    except Exception:
        return "unknown"

async def grab_ftp(host: str, port: int = 21, timeout: float = 2.0) -> str:
    try:
        reader, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=timeout)
        data = await asyncio.wait_for(reader.read(512), timeout=timeout)
        writer.close()
        await writer.wait_closed()
        banner = data.decode('utf-8', errors='ignore').strip()
        return banner[3:].strip() if banner.startswith("220") else banner
    except Exception:
        return "unknown"

async def grab_generic(host: str, port: int, timeout: float = 2.0) -> str:
    """
    Generic-граббер для портов без выделенного хендлера.
    ВАЖНО: многие протоколы (SMB/445, X11/6000, AJP/8009, drb/8787) сами
    НЕ присылают баннер — они ждут, что клиент заговорит первым.
    Без отдельного таймаута на read() это виснет на месте (проверено тестом).
    Поэтому: если за timeout секунд ничего не пришло — это тоже валидный
    результат "порт открыт, но молчит", а не ошибка.
    """
    try:
        reader, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=timeout)
        try:
            data = await asyncio.wait_for(reader.read(512), timeout=timeout)
            banner = data.decode('utf-8', errors='ignore').strip()
            result = banner if banner else "raw open (no banner)"
        except asyncio.TimeoutError:
            # Порт открыт и принял соединение, но не прислал баннер за timeout —
            # типично для SMB/X11/AJP/RMI. Это НЕ ошибка, порт точно открыт.
            result = "open, no banner (protocol expects client to speak first)"
        writer.close()
        await writer.wait_closed()
        return result
    except Exception:
        return "unknown"


async def check_tomcat_default_creds(host: str, port: int, timeout: float = 2.0) -> dict:
    """
    РОВНО ОДНА целевая проверка: пускает ли Tomcat Manager на дефолтных
    учётных данных tomcat:tomcat (классика Metasploitable 2, порт 8180).
    Не брутфорс — один HTTP-запрос с Basic Auth.
    """
    creds = base64.b64encode(b"tomcat:tomcat").decode("ascii")
    payload = (
        f"GET /manager/html HTTP/1.0\r\n"
        f"Host: {host}\r\n"
        f"Authorization: Basic {creds}\r\n"
        f"\r\n"
    ).encode("utf-8")

    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port), timeout=timeout
        )
        writer.write(payload)
        await writer.drain()

        data = await asyncio.wait_for(reader.read(200), timeout=timeout)
        writer.close()
        await writer.wait_closed()

        response_line = data.decode("utf-8", errors="ignore").split("\r\n", 1)[0]

        if " 200 " in response_line:
            return {"status": "open", "weak_creds": True, "detail": "tomcat:tomcat принят, /manager доступен"}
        elif " 401 " in response_line or " 403 " in response_line:
            return {"status": "open", "weak_creds": False}
        else:
            return {"status": "open", "weak_creds": False, "detail": f"неожиданный ответ: {response_line}"}

    except Exception:
        return {"status": "closed"}