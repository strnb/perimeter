import asyncio
import logging

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

# Безопасный импорт: если pymongo не установлен, скрипт не упадет при старте
try:
    from pymongo import MongoClient
    from pymongo.errors import ServerSelectionTimeoutError, OperationFailure

    PYMONGO_AVAILABLE = True
except ImportError:
    PYMONGO_AVAILABLE = False


async def check_redis(host: str, port: int = 6379, timeout: float = 2.0) -> dict:
    """Задачи 9-11: Проверка доступности Redis (работает БЕЗ внешних библиотек)"""
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port),
            timeout=timeout
        )
        writer.write(b"PING\r\n")
        await writer.drain()

        data = await reader.read(1024)
        writer.close()
        await writer.wait_closed()

        response = data.decode('utf-8', errors='ignore').strip()

        if response.startswith("+PONG"):
            return {"status": "open", "auth": False}
        elif "NOAUTH" in response or "ERR AUTH" in response:
            return {"status": "open", "auth": True}
        else:
            return {"status": "closed"}
    except Exception:
        return {"status": "closed"}


def _sync_mongo_check(host: str, port: int) -> dict:
    import asyncio
    import logging
    from pymongo import MongoClient
    from pymongo.errors import ServerSelectionTimeoutError, OperationFailure

    logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

    async def check_redis(host: str, port: int = 6379, timeout: float = 2.0) -> dict:
        """
        Задачи 9-11: Проверка доступности Redis и наличия авторизации.
        Отправляет сырую команду PING в формате протокола RESP.
        """
        try:
            # Открываем TCP соединение
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port),
                timeout=timeout
            )

            # Отправляем команду PING\r\n (в протоколе RESP это может быть и просто строка, и массив)
            writer.write(b"PING\r\n")
            await writer.drain()

            # Читаем ответ от сервера
            data = await reader.read(1024)
            writer.close()
            await writer.wait_closed()

            response = data.decode('utf-8', errors='ignore').strip()

            # Анализируем ответ RESP
            if response.startswith("+PONG"):
                return {"status": "open", "auth": False}
            elif "NOAUTH" in response or "ERR AUTH" in response:
                return {"status": "open", "auth": True}
            else:
                return {"status": "closed"}

        except Exception:
            return {"status": "closed"}

    def _sync_mongo_check(host: str, port: int) -> dict:
        """Вспомогательная синхронная функция для проверки Mongo через pymongo."""
        client = None
        try:
            # Инициализируем клиент с жестким таймаутом в 2 секунды (2000 мс)
            client = MongoClient(host, port, serverSelectionTimeoutMS=2000)

            # server_info() принудительно отправляет запрос к БД
            client.server_info()
            return {"status": "open", "auth": False}

        except OperationFailure:
            # Подключились, но БД требует авторизацию (базовые команды запрещены)
            return {"status": "open", "auth": True}

        except ServerSelectionTimeoutError:
            # Не смогли подключиться за 2 секунды (сервер выключен / закрыт файрволом)
            return {"status": "closed"}

        except Exception:
            return {"status": "closed"}
        finally:
            if client:
                client.close()

    async def check_mongo(host: str, port: int = 27017) -> dict:
        """
        Задачи 12-13: Проверка доступности MongoDB.
        Выполняет синхронный вызов pymongo в отдельном потоке, чтобы не блокировать event loop.
        """
        # asyncio.to_thread отправляет синхронную задачу в пул потоков (Thread Pool)
        return await asyncio.to_thread(_sync_mongo_check, host, port)

async def check_mongo(host: str, port: int = 27017) -> dict:
    """Задачи 12-13: Проверка MongoDB (не блокирует поток)"""
    if not PYMONGO_AVAILABLE:
        logging.warning("[-] Сканирование Mongo пропущено: библиотека pymongo не установлена.")
        return {"status": "error", "reason": "pymongo_missing"}
    return await asyncio.to_thread(_sync_mongo_check, host, port)