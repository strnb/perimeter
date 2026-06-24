import asyncio
import logging
from typing import TypedDict, Optional

# Настройка логгера
logger = logging.getLogger(__name__)

try:
    from pymongo import MongoClient
    from pymongo.errors import ServerSelectionTimeoutError, OperationFailure
    PYMONGO_AVAILABLE = True
except ImportError:
    PYMONGO_AVAILABLE = False

class DBCheckResult(TypedDict):
    status: str
    auth: Optional[bool]
    reason: Optional[str]

async def check_redis(host: str, port: int = 6379, timeout: float = 2.0) -> DBCheckResult:
    """Проверка доступности Redis по протоколу RESP."""
    reader, writer = None, None
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port),
            timeout=timeout
        )
        writer.write(b"PING\r\n")
        await writer.drain()

        data = await reader.read(1024)
        response = data.decode('utf-8', errors='ignore').strip()

        if response.startswith("+PONG"):
            return {"status": "open", "auth": False, "reason": None}
        elif "NOAUTH" in response or "ERR AUTH" in response:
            return {"status": "open", "auth": True, "reason": "auth_required"}
        
        return {"status": "closed", "auth": None, "reason": "unexpected_response"}
    except Exception as e:
        logger.debug(f"Redis check error for {host}:{port}: {e}")
        return {"status": "closed", "auth": None, "reason": str(e)}
    finally:
        if writer:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass

def _sync_mongo_check(host: str, port: int) -> DBCheckResult:
    """Синхронный воркер для проверки MongoDB."""
    if not PYMONGO_AVAILABLE:
        return {"status": "error", "auth": None, "reason": "pymongo_missing"}

    client = None
    try:
        client = MongoClient(host, port, serverSelectionTimeoutMS=2000)
        client.server_info()
        return {"status": "open", "auth": False, "reason": None}
    except OperationFailure:
        return {"status": "open", "auth": True, "reason": "auth_required"}
    except ServerSelectionTimeoutError:
        return {"status": "closed", "auth": None, "reason": "timeout"}
    except Exception as e:
        return {"status": "closed", "auth": None, "reason": str(e)}
    finally:
        if client:
            client.close()

async def check_mongodb(host: str, port: int = 27017) -> DBCheckResult:
    """Асинхронная обертка для проверки MongoDB."""
    if not PYMONGO_AVAILABLE:
        return {"status": "error", "auth": None, "reason": "pymongo_missing"}
    
    return await asyncio.to_thread(_sync_mongo_check, host, port)
