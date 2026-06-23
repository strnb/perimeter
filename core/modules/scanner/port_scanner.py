import asyncio
import logging

# Настройка базового логирования для отладки
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

async def scan_port(host: str, port: int, timeout: float = 1.0) -> bool:
    """
    Сканирует один порт на указанном хосте.
    Возвращает True, если порт открыт, и False, если закрыт или таймаут.
    """
    try:
        # Пытаемся установить TCP-соединение с ограничением по времени
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port), 
            timeout=timeout
        )
        
        # Если соединение успешно, обязательно закрываем сокет
        writer.close()
        await writer.wait_closed()
        return True

    except asyncio.TimeoutError:
        # Порт не ответил за указанное время (скорее всего, дропается файрволом)
        return False
        
    except (ConnectionRefusedError, OSError) as e:
        # ConnectionRefusedError -> хост ответил RST пакетом (порт закрыт)
        # OSError -> общие ошибки сети (хост недоступен, нет маршрута и т.д.)
        return False