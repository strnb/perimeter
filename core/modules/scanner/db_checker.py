import asyncio
import logging

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

try:
    from pymongo import MongoClient
    from pymongo.errors import ServerSelectionTimeoutError, OperationFailure

    PYMONGO_AVAILABLE = True
except ImportError:
    PYMONGO_AVAILABLE = False

try:
    import pymysql

    PYMYSQL_AVAILABLE = True
except ImportError:
    PYMYSQL_AVAILABLE = False


async def check_redis(host: str, port: int = 6379, timeout: float = 2.0) -> dict:
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
    if not PYMONGO_AVAILABLE:
        return {"status": "error", "reason": "pymongo_missing"}

    client = None
    try:
        client = MongoClient(host, port, serverSelectionTimeoutMS=2000)
        client.server_info()
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
    if not PYMONGO_AVAILABLE:
        return {"status": "error", "reason": "pymongo_missing"}
    return await asyncio.to_thread(_sync_mongo_check, host, port)


def _sync_mysql_check(host: str, port: int) -> dict:
    """
    Синхронный воркер: РОВНО ОДНА целевая попытка логина root без пароля.
    Это не брутфорс и не подбор словаря — единственная проверка
    самого известного misconfiguration MySQL на Metasploitable 2.
    """
    conn = None
    try:
        conn = pymysql.connect(
            host=host, port=port,
            user="root", password="",
            connect_timeout=2,
        )
        conn.close()
        return {"status": "open", "weak_creds": True, "detail": "root без пароля"}
    except pymysql.err.OperationalError:
        # Подключились к MySQL, но логин root/'' не прошёл — сервер защищён
        return {"status": "open", "weak_creds": False}
    except Exception:
        return {"status": "closed"}


async def check_mysql_weak_creds(host: str, port: int = 3306) -> dict:
    """Проверка classic MS2-кейса: MySQL root без пароля (одна попытка, не брутфорс)."""
    if not PYMYSQL_AVAILABLE:
        logging.warning("[-] Проверка MySQL пропущена: библиотека pymysql не установлена.")
        return {"status": "error", "reason": "pymysql_missing"}

    return await asyncio.to_thread(_sync_mysql_check, host, port)