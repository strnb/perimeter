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
    except OperationFailure:
        # ВАЖНО: подключились успешно, сервер ОТВЕЧАЕТ, но просит авторизацию —
        # это значит порт открыт и защищён, а не недоступен
        return {"status": "open", "auth": True, "vulnerable": False}
    except ServerSelectionTimeoutError:
        # ВАЖНО: сервер вообще не отвечает за 2 секунды — это закрытый/недоступный
        # порт, а НЕ "открыт и защищён". Раньше эти два случая были слиты в один
        # except и оба маппились на "open" — настоящий сервер сходу путался
        # с просто закрытым портом.
        return {"status": "closed", "vulnerable": False}
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


async def check_vnc(host: str, port: int = 5900, timeout: float = 2.0) -> dict:
    """Активный VNC-пробник: читает RFB protocol version banner."""
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port), timeout=timeout
        )
        data = await asyncio.wait_for(reader.read(32), timeout=timeout)
        writer.close()
        await writer.wait_closed()

        banner = data.decode("ascii", errors="ignore").strip()
        if banner.startswith("RFB "):
            return {"status": "open", "banner": banner, "vulnerable": False, "detail": "VNC protocol confirmed"}

        return {"status": "open", "banner": banner or "no VNC banner", "vulnerable": False}
    except Exception:
        return {"status": "closed", "vulnerable": False}


async def check_telnet_banner(host: str, port: int = 23, timeout: float = 2.0) -> dict:
    """Активный Telnet-пробник: читает приветствие/login prompt."""
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port), timeout=timeout
        )

        try:
            data = await asyncio.wait_for(reader.read(512), timeout=timeout)
        except asyncio.TimeoutError:
            writer.write(b"\r\n")
            await writer.drain()
            data = await asyncio.wait_for(reader.read(512), timeout=timeout)

        writer.close()
        await writer.wait_closed()

        banner = data.decode("utf-8", errors="ignore").strip()
        return {"status": "open", "banner": banner or "telnet prompt detected", "vulnerable": True}
    except Exception:
        return {"status": "closed", "vulnerable": False}


async def check_rpcbind(host: str, port: int = 111, timeout: float = 2.0) -> dict:
    """Активный SunRPC/rpcbind NULL call over TCP."""
    rpc_null_call = (
        b"\x80\x00\x00\x28"
        b"\x12\x34\x56\x78"
        b"\x00\x00\x00\x00"
        b"\x00\x00\x00\x02"
        b"\x00\x01\x86\xa0"
        b"\x00\x00\x00\x02"
        b"\x00\x00\x00\x00"
        b"\x00\x00\x00\x00\x00\x00\x00\x00"
        b"\x00\x00\x00\x00\x00\x00\x00\x00"
    )

    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port), timeout=timeout
        )
        writer.write(rpc_null_call)
        await writer.drain()
        data = await asyncio.wait_for(reader.read(128), timeout=timeout)
        writer.close()
        await writer.wait_closed()

        if len(data) >= 8 and data[4:8] == b"\x12\x34\x56\x78":
            return {"status": "open", "banner": "rpcbind NULL call accepted", "vulnerable": True}
        return {"status": "open", "banner": f"rpcbind-like response ({len(data)} bytes)", "vulnerable": False}
    except Exception:
        return {"status": "closed", "vulnerable": False}


async def check_nfs(host: str, port: int = 2049, timeout: float = 2.0) -> dict:
    """Активный NFS NULL call: подтверждает, что порт 2049 говорит как NFS."""
    nfs_null_call = (
        b"\x80\x00\x00\x28"
        b"\x87\x65\x43\x21"
        b"\x00\x00\x00\x00"
        b"\x00\x00\x00\x02"
        b"\x00\x01\x86\xa3"
        b"\x00\x00\x00\x03"
        b"\x00\x00\x00\x00"
        b"\x00\x00\x00\x00\x00\x00\x00\x00"
        b"\x00\x00\x00\x00\x00\x00\x00\x00"
    )

    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port), timeout=timeout
        )
        writer.write(nfs_null_call)
        await writer.drain()
        data = await asyncio.wait_for(reader.read(128), timeout=timeout)
        writer.close()
        await writer.wait_closed()

        if len(data) >= 8 and data[4:8] == b"\x87\x65\x43\x21":
            return {"status": "open", "banner": "NFS v3 NULL call accepted", "vulnerable": True}
        return {"status": "open", "banner": f"NFS-like response ({len(data)} bytes)", "vulnerable": False}
    except Exception:
        return {"status": "closed", "vulnerable": False}


async def check_irc(host: str, port: int = 6667, timeout: float = 2.0) -> dict:
    """Активный IRC-пробник: регистрирует временный nick и читает welcome/version banner."""
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port), timeout=timeout
        )
        writer.write(b"NICK perimeter_probe\r\nUSER perimeter 0 * :Perimeter Probe\r\n")
        await writer.drain()
        data = await asyncio.wait_for(reader.read(1024), timeout=timeout)
        writer.close()
        await writer.wait_closed()

        banner = data.decode("utf-8", errors="ignore").strip()
        is_unreal = "unreal" in banner.lower()
        return {
            "status": "open",
            "banner": banner or "IRC service detected",
            "vulnerable": is_unreal,
            "detail": "UnrealIRCd banner detected" if is_unreal else "IRC handshake completed",
        }
    except Exception:
        return {"status": "closed", "vulnerable": False}


async def check_distccd(host: str, port: int = 3632, timeout: float = 2.0) -> dict:
    """Активный distccd-пробник: отправляет безвредный некорректный magic и ждёт ошибку протокола."""
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port), timeout=timeout
        )
        writer.write(b"DIST00000001")
        await writer.drain()
        data = await asyncio.wait_for(reader.read(256), timeout=timeout)
        writer.close()
        await writer.wait_closed()

        banner = data.decode("utf-8", errors="ignore").strip()
        markers = ("DIST", "DONE", "DOTO", "ERR", "distcc")
        detected = any(marker.lower() in banner.lower() for marker in markers)
        return {
            "status": "open",
            "banner": banner or "distccd port open",
            "vulnerable": detected,
            "detail": "distccd protocol response detected" if detected else "distccd port open, protocol not confirmed",
        }
    except Exception:
        return {"status": "closed", "vulnerable": False}


async def check_bind_shell(host: str, port: int, timeout: float = 2.0) -> dict:
    """Безопасная проверка bind shell: выполняет только `id` и ищет uid= в ответе."""
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port), timeout=timeout
        )
        writer.write(b"id\n")
        await writer.drain()
        data = await asyncio.wait_for(reader.read(512), timeout=timeout)
        writer.close()
        await writer.wait_closed()

        output = data.decode("utf-8", errors="ignore").strip()
        vulnerable = "uid=" in output
        return {
            "status": "open",
            "banner": output or "bind shell port open",
            "vulnerable": vulnerable,
            "detail": "bind shell confirmed via id" if vulnerable else "port open, shell not confirmed",
        }
    except Exception:
        return {"status": "closed", "vulnerable": False}


async def check_smb_ghost(host: str, port: int = 445, timeout: float = 2.0) -> dict:
    """
    Активный SMB-пробник: отправляет SMB1 Negotiate Protocol Request.

    ВАЖНО: мы уже подтвердили на реальной Metasploitable 2, что SMB НЕ
    присылает ничего по факту простого TCP-коннекта -- сервис молчит, пока
    клиент сам не заговорит первым. Прежняя версия этой функции этого не
    делала и просто слушала тишину, поэтому всегда ошибочно решала, что
    порт закрыт.

    ОСТОРОЖНО: байты SMB1-пакета ниже -- классическая для security-тулинга
    последовательность, но она НЕ была проверена против настоящего сервера
    в этой среде (нет сети). Обязательно прогнать на реальной MS2 перед
    тем, как показывать на демо -- если формат ответа окажется другим,
    функция всё равно не упадёт и не соврёт "closed", но точную версию
    может не вытащить.
    """
    # NetBIOS Session Service header (4 байта) + SMB1 Negotiate Protocol Request,
    # предлагающий диалект "NT LM 0.12" (общий знаменатель почти для всех версий)
    smb_negotiate = (
        b"\x00\x00\x00\x2f"          # NetBIOS header: длина SMB-сообщения = 47 байт
        b"\xffSMB\x72"               # SMB Protocol ID + Command (SMB_COM_NEGOTIATE)
        b"\x00\x00\x00\x00"          # NT Status
        b"\x00"                      # Flags
        b"\x00\x00"                  # Flags2
        b"\x00\x00"                  # Process ID High
        b"\x00\x00\x00\x00\x00\x00\x00\x00"  # Signature
        b"\x00\x00"                  # Reserved
        b"\x00\x00"                  # Tree ID
        b"\xff\xfe"                  # Process ID
        b"\x00\x00"                  # User ID
        b"\x00\x00"                  # Multiplex ID
        b"\x00"                      # Word Count = 0
        b"\x0c\x00"                  # Byte Count = 12
        b"\x02NT LM 0.12\x00"        # Dialect string
    )

    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port), timeout=timeout
        )

        writer.write(smb_negotiate)
        await writer.drain()

        try:
            data = await asyncio.wait_for(reader.read(1024), timeout=timeout)
        except asyncio.TimeoutError:
            # ВАЖНО: коннект прошёл успешно (порт точно открыт), просто
            # не ответил на негоушиэйт за timeout -- это НЕ "закрыт".
            writer.close()
            await writer.wait_closed()
            return {
                "status": "open", "banner": "", "vulnerable": False,
                "detail": "SMB-порт открыт, но не ответил на Negotiate Protocol Request",
            }

        writer.close()
        await writer.wait_closed()

        is_smb_response = len(data) > 8 and data[4:8] == b"\xffSMB"
        banner_text = data[32:].decode("utf-8", errors="ignore").strip("\x00").strip()

        if is_smb_response:
            return {
                "status": "open", "banner": banner_text, "vulnerable": True,
                "detail": f"SMB Negotiate подтверждён, данные после заголовка: {banner_text[:80]!r}",
            }

        return {"status": "open", "banner": banner_text, "vulnerable": False}

    except Exception:
        return {"status": "closed", "vulnerable": False}