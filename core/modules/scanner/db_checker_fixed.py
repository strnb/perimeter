import asyncio
import logging

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

try:
    from pymongo import MongoClient
    from pymongo.errors import ServerSelectionTimeoutError, OperationFailure

    PYMONGO_AVAILABLE = True
except ImportError:
    PYMONGO_AVAILABLE = False


async def check_redis(host: str, port: int = 6379, timeout: float = 2.0) -> dict:
    """Проверка доступности Redis по сырому протоколу RESP."""
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
    """Синхронный воркер для MongoClient, вынесенный на верхний уровень."""
    if not PYMONGO_AVAILABLE:
        return {"status": "error", "reason": "pymongo_missing"}

    client = None
    try:
        client = MongoClient(host, port, serverSelectionTimeoutMS=2000)
        client.server_info()  # Триггерим реальное подключение
        return {"status": "open", "auth": False}
    except OperationFailure:
        return {"status": "open", "auth": True}
    except ServerSelectionTimeoutError:
        return {"status": "closed"}
    except Exception:
        return {"status": "closed"}
    finally:
        if client:
            client.close()


async def check_mongo(host: str, port: int = 27017) -> dict:
    """Безопасный вызов проверки MongoDB в отдельном потоке."""
    if not PYMONGO_AVAILABLE:
        return {"status": "error", "reason": "pymongo_missing"}
    # Теперь вызывается корректная функция верхнего уровня
    return await asyncio.to_thread(_sync_mongo_check, host, port)
