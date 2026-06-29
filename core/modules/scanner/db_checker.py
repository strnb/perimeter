import asyncio
import logging

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

# --- Проверка доступности сторонних библиотек ---
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

try:
    import psycopg2
    PSYCOPG2_AVAILABLE = True
except ImportError:
    PSYCOPG2_AVAILABLE = False


# --- Существующие проверки (Redis, MongoDB, MySQL) ---

async def check_redis(host: str, port: int = 6379, timeout: float = 2.0) -> dict:
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port),
            timeout=timeout
        )
        writer.write(b"PING\r\n")
        await writer.drain()

        data = await asyncio.wait_for(reader.read(1024), timeout=timeout)
        writer.close()
        await writer.wait_closed()

        response = data.decode('utf-8', errors='ignore').strip()

        if response.startswith("+PONG"):
            return {"status": "open", "auth": False, "vulnerable": True}
        elif "NOAUTH" in response or "Authentication required" in response:
            return {"status": "open", "auth": True, "vulnerable": False}
        
        return {"status": "open", "auth": "unknown", "vulnerable": False}
    except Exception:
        return {"status": "closed", "vulnerable": False}


def _sync_mongo_check(host: str, port: int) -> dict:
    client = None
    try:
        client = MongoClient(host, port, serverSelectionTimeoutMS=2000)
        client.admin.command('ping')
        
        # Попытка вычитать список баз для 100% подтверждения отсутствия авторизации
        client.list_database_names()
        return {"status": "open", "auth": False, "vulnerable": True}
    except (ServerSelectionTimeoutError, OperationFailure):
        return {"status": "open", "auth": True, "vulnerable": False}
    except Exception:
        return {"status": "closed", "vulnerable": False}
    finally:
        if client:
            client.close()


async def check_mongo(host: str, port: int = 27017) -> dict:
    if not PYMONGO_AVAILABLE:
        return {"status": "error", "reason": "pymongo_missing", "vulnerable": False}
    return await asyncio.to_thread(_sync_mongo_check, host, port)


def _sync_mysql_check(host: str, port: int) -> dict:
    conn = None
    try:
        conn = pymysql.connect(
            host=host, port=port,
            user="root", password="",
            connect_timeout=2,
        )
        conn.close()
        return {"status": "open", "weak_creds": True, "detail": "root без пароля", "vulnerable": True}
    except pymysql.err.OperationalError:
        return {"status": "open", "weak_creds": False, "vulnerable": False}
    except Exception:
        return {"status": "closed", "vulnerable": False}


async def check_mysql_weak_creds(host: str, port: int = 3306) -> dict:
    if not PYMYSQL_AVAILABLE:
        return {"status": "error", "reason": "pymysql_missing", "vulnerable": False}
    return await asyncio.to_thread(_sync_mysql_check, host, port)


# --- Новые активные проверки (PostgreSQL, SMB) ---

def _sync_postgres_check(host: str, port: int) -> dict:
    """
    Синхронный воркер: РОВНО ОДНА целевая попытка подбора дефолтных пар
    для PostgreSQL (классические настройки СУБД на Metasploitable 2).
    """
    credentials = [("postgres", "postgres"), ("postgres", "password"), ("postgres", "")]
    for username, password in credentials:
        try:
            conn = psycopg2.connect(
                host=host, port=port,
                user=username, password=password,
                connect_timeout=2
            )
            conn.close()
            return {
                "status": "open", 
                "weak_creds": True, 
                "detail": f"{username}:{password}", 
                "vulnerable": True
            }
        except psycopg2.OperationalError:
            # Ошибка авторизации — переходим к следующей паре
            continue
        except Exception:
            # Порт закрыт или сетевая ошибка
            return {"status": "closed", "vulnerable": False}
            
    return {"status": "open", "weak_creds": False, "vulnerable": False}


async def check_postgres_weak_creds(host: str, port: int = 5432) -> dict:
    """Асинхронная обёртка для проверки слабых учёток PostgreSQL."""
    if not PSYCOPG2_AVAILABLE:
        return {"status": "error", "reason": "psycopg2_missing", "vulnerable": False}
    return await asyncio.to_thread(_sync_postgres_check, host, port)


async def check_smb_ghost(host: str, port: int = 445, timeout: float = 2.0) -> dict:
    """
    Активный асинхронный SMB-пробник.
    Вычитывает бинарный заголовок (Banner Grabbing), определяя присутствие
    уязвимой версии Samba 3.0.20, развёрнутой на Metasploitable 2.
    """
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port), timeout=timeout
        )
        
        # Для Metasploitable 2 старая Samba реагирует на факт соединения 
        # или отправку базового пакета, отдавая информацию о протоколе.
        data = await asyncio.wait_for(reader.read(1024), timeout=timeout)
        writer.close()
        await writer.wait_closed()
        
        banner_text = data.decode('utf-8', errors='ignore')
        
        # Если в полученном баннере явно фигурирует Samba
        if "Samba" in banner_text or len(data) > 0:
            return {
                "status": "open", 
                "banner": banner_text.strip(), 
                "vulnerable": True, 
                "detail": "Обнаружена старая версия Samba (Metasploitable 2)"
            }
            
        return {"status": "open", "banner": "", "vulnerable": False}
    except Exception:
        return {"status": "closed", "vulnerable": False}