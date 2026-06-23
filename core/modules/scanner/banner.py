import asyncio
import re
import ssl
import logging

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

# Регулярное выражение для поиска заголовка Server в HTTP ответе (регистронезависимое)
HTTP_SERVER_REGEX = re.compile(r"Server:\s*(.+)", re.IGNORECASE)


async def grab_http(host: str, port: int, timeout: float = 2.0) -> str:
    """
    Задача 6: Получает HTTP баннер (заголовок Server).
    Поддерживает HTTP и HTTPS (через SSL).
    """
    # Формируем сырой HTTP-запрос
    payload = "GET / HTTP/1.0\r\nHost: {}\r\n\r\n".format(host).encode('utf-8')

    try:
        # Если порт 443, настраиваем SSL-контекст
        ssl_context = None
        if port == 443:
            ssl_context = ssl.create_default_context()
            # Отключаем строгую проверку сертификатов для ИБ-сканера, чтобы не падать на самоподписанных SSL
            ssl_context.check_hostname = False
            ssl_context.verify_mode = ssl.CERT_NONE

        # Открываем асинхронное соединение
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port, ssl=ssl_context),
            timeout=timeout
        )

        # Отправляем запрос
        writer.write(payload)
        await writer.drain()

        # Читаем заголовки ответа (обычно 1024 байт хватает для заголовков)
        data = await reader.read(1024)
        writer.close()
        await writer.wait_closed()

        response_text = data.decode('utf-8', errors='ignore')

        # Ищем заголовок Server:
        match = HTTP_SERVER_REGEX.search(response_text)
        if match:
            return match.group(1).strip()

        return "unknown"

    except Exception as e:
        logging.debug(f"[-] Ошибка HTTP граббинга на {host}:{port} -> {e}")
        return "unknown"


async def grab_ssh(host: str, port: int = 22, timeout: float = 2.0) -> str:
    """
    Задача 7: Получает SSH баннер.
    SSH-сервер сам присылает строку приветствия сразу после TCP-подключения.
    """
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port),
            timeout=timeout
        )

        # Читаем первые 256 байт ответа сервера
        data = await reader.read(256)
        writer.close()
        await writer.wait_closed()

        banner = data.decode('utf-8', errors='ignore').strip()
        return banner if banner else "unknown"

    except Exception:
        return "unknown"


async def grab_ftp(host: str, port: int = 21, timeout: float = 2.0) -> str:
    """
    Задача 8: Получает FTP баннер.
    FTP-сервер сразу после подключения возвращает строку, начинающуюся с кода 220.
    """
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port),
            timeout=timeout
        )

        # Читаем приветствие (строка 220)
        data = await reader.read(512)
        writer.close()
        await writer.wait_closed()

        banner = data.decode('utf-8', errors='ignore').strip()
        # Отрезаем код 220 для красоты, если он есть
        if banner.startswith("220"):
            banner = banner[3:].strip()

        return banner if banner else "unknown"

    except Exception:
        return "unknown"