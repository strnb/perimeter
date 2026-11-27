import asyncio
import re
import logging

# Библиотека не настраивает корневой логгер: иначе любой импорт включает
# INFO-логи httpx и прочих зависимостей у пользователя.
logger = logging.getLogger(__name__)

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


# ---------------------------------------------------------------------------
# Redis
# ---------------------------------------------------------------------------

async def check_redis(host: str, port: int = 6379, timeout: float = 2.0) -> dict:
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port), timeout=timeout
        )
        writer.write(b"PING\r\n")
        await writer.drain()
        data = await asyncio.wait_for(reader.read(1024), timeout=timeout)
        writer.close()
        await writer.wait_closed()
        response = data.decode("utf-8", errors="ignore").strip()
        if response.startswith("+PONG"):
            return {"status": "open", "auth": False, "vulnerable": True}
        elif "NOAUTH" in response or "Authentication required" in response:
            return {"status": "open", "auth": True, "vulnerable": False}
        return {"status": "open", "auth": "unknown", "vulnerable": False}
    except Exception:
        return {"status": "closed", "vulnerable": False}


# ---------------------------------------------------------------------------
# MongoDB
# ---------------------------------------------------------------------------

def _sync_mongo_check(host: str, port: int) -> dict:
    client = None
    try:
        client = MongoClient(host, port, serverSelectionTimeoutMS=2000)
        client.admin.command("ping")
        client.list_database_names()
        return {"status": "open", "auth": False, "vulnerable": True}
    except OperationFailure:
        # Подключились успешно, но операция отклонена — нужна авторизация.
        # ВАЖНО: отдельный except от ServerSelectionTimeoutError — иначе
        # недоступный сервер (таймаут) ошибочно помечается status="open".
        return {"status": "open", "auth": True, "vulnerable": False}
    except ServerSelectionTimeoutError:
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


# ---------------------------------------------------------------------------
# MySQL
# ---------------------------------------------------------------------------

def _sync_mysql_check(host: str, port: int) -> dict:
    conn = None
    try:
        conn = pymysql.connect(
            host=host, port=port,
            user="root", password="",
            connect_timeout=2,
        )
        conn.close()
        return {"status": "open", "weak_creds": True,
                "detail": "root without password", "vulnerable": True}
    except pymysql.err.OperationalError:
        return {"status": "open", "weak_creds": False, "vulnerable": False}
    except Exception:
        return {"status": "closed", "vulnerable": False}


async def check_mysql_weak_creds(host: str, port: int = 3306) -> dict:
    if not PYMYSQL_AVAILABLE:
        return {"status": "error", "reason": "pymysql_missing", "vulnerable": False}
    return await asyncio.to_thread(_sync_mysql_check, host, port)


# ---------------------------------------------------------------------------
# PostgreSQL
# ---------------------------------------------------------------------------

def _sync_postgres_check(host: str, port: int) -> dict:
    credentials = [
        ("postgres", "postgres"),
        ("postgres", "password"),
        ("postgres", ""),
    ]
    for username, password in credentials:
        try:
            conn = psycopg2.connect(
                host=host, port=port,
                user=username, password=password,
                connect_timeout=2
            )
            conn.close()
            return {"status": "open", "weak_creds": True,
                    "detail": f"{username}:{password}", "vulnerable": True}
        except psycopg2.OperationalError:
            continue
        except Exception:
            return {"status": "closed", "vulnerable": False}
    return {"status": "open", "weak_creds": False, "vulnerable": False}


async def check_postgres_weak_creds(host: str, port: int = 5432) -> dict:
    if not PSYCOPG2_AVAILABLE:
        return {"status": "error", "reason": "psycopg2_missing", "vulnerable": False}
    return await asyncio.to_thread(_sync_postgres_check, host, port)


# ---------------------------------------------------------------------------
# SMB / Samba
# ---------------------------------------------------------------------------

async def check_smb_ghost(host: str, port: int = 445, timeout: float = 2.0) -> dict:
    """
    Активный SMB-пробник — отправляет SMB1 Negotiate Protocol Request.

    ВАЖНО: SMB-сервер НИКОГДА не говорит первым после TCP-коннекта.
    Пассивный reader.read() всегда даст таймаут и вернёт status=closed
    для реально открытого порта. Это проверено на реальной Metasploitable 2.

    Алгоритм: отправляем Negotiate → ждём ответ с магическим \xffSMB →
    если пришёл — SMB подтверждён, парсим WORKGROUP из хвоста ответа.
    """
    smb_negotiate = (
        b"\x00\x00\x00\x2f"
        b"\xffSMB\x72"
        b"\x00\x00\x00\x00"
        b"\x00"
        b"\x00\x00"
        b"\x00\x00"
        b"\x00\x00\x00\x00\x00\x00\x00\x00"
        b"\x00\x00"
        b"\x00\x00"
        b"\xff\xfe"
        b"\x00\x00"
        b"\x00\x00"
        b"\x00"
        b"\x0c\x00"
        b"\x02NT LM 0.12\x00"
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
            writer.close()
            return {
                "status": "open", "banner": "", "vulnerable": False,
                "detail": "SMB-порт открыт, но не ответил на Negotiate",
            }

        writer.close()
        await writer.wait_closed()

        is_smb = len(data) > 8 and data[4:8] == b"\xffSMB"
        banner = data[32:].decode("utf-8", errors="ignore").strip("\x00").strip()

        if is_smb:
            # Подтверждён только протокол, а не уязвимость: ответ на Negotiate
            # даёт любой SMB-сервер, включая полностью обновлённый Windows.
            return {
                "status": "open", "banner": banner, "vulnerable": False,
                "smb_confirmed": True,
                "detail": f"SMB Negotiate подтверждён, данные: {banner[:80]!r}",
            }
        return {"status": "open", "banner": banner, "vulnerable": False}
    except Exception:
        return {"status": "closed", "vulnerable": False}


# ---------------------------------------------------------------------------
# Telnet
# ---------------------------------------------------------------------------

async def check_telnet_banner(host: str, port: int = 23, timeout: float = 2.0) -> dict:
    """
    Читает IAC-байты приветствия Telnet.
    ФИКС: reader.read() обёрнут в wait_for — без этого зависает если
    сервис принял коннект но молчит (подтверждено тестом: 8 сек вместо 2).
    """
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port), timeout=timeout
        )
        try:
            data = await asyncio.wait_for(reader.read(512), timeout=timeout)
        except asyncio.TimeoutError:
            writer.close()
            return {"status": "open", "banner": "Telnet open (no prompt)",
                    "vulnerable": True}
        writer.close()
        await writer.wait_closed()
        banner = data.decode("utf-8", errors="ignore").strip()
        return {"status": "open", "banner": banner or "telnet prompt detected",
                "vulnerable": True}
    except Exception:
        return {"status": "closed", "vulnerable": False}


# ---------------------------------------------------------------------------
# RPCbind / Portmapper (порт 111)
# ---------------------------------------------------------------------------

# Корректный RPC NULL call: 10 полей * 4 байта = 40 байт (соответствует record mark 0x28)
_RPC_NULL = bytes.fromhex(
    "80000028"   # record mark: last fragment=1, length=40
    "12345678"   # XID
    "00000000"   # direction: CALL
    "00000002"   # RPC version: 2
    "000186a0"   # program: portmapper (100000)
    "00000002"   # program version: 2
    "00000000"   # procedure: NULL (0)
    "00000000"   # credentials: flavor AUTH_NULL
    "00000000"   # credentials: length 0
    "00000000"   # verifier: flavor AUTH_NULL
    "00000000"   # verifier: length 0
)


async def check_rpcbind(host: str, port: int = 111, timeout: float = 2.0) -> dict:
    """
    Отправляет корректный RPC NULL call и проверяет что XID вернулся.
    ФИКС: исходный пакет в документе был неполным (32 байта вместо 40):
    отсутствовали поля cred_len и verif_len.
    """
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port), timeout=timeout
        )
        writer.write(_RPC_NULL)
        await writer.drain()
        data = await asyncio.wait_for(reader.read(512), timeout=timeout)
        writer.close()
        await writer.wait_closed()

        # Проверяем что XID из ответа совпадает с нашим
        xid_match = len(data) >= 8 and data[4:8] == b"\x12\x34\x56\x78"
        return {
            "status": "open",
            "vulnerable": xid_match,
            "banner": "rpcbind NULL call accepted" if xid_match
                      else f"rpcbind response ({len(data)} bytes, XID mismatch)",
        }
    except Exception:
        return {"status": "closed", "vulnerable": False}


# ---------------------------------------------------------------------------
# NFS (порт 2049)
# ---------------------------------------------------------------------------

async def check_nfs(host: str, port: int = 2049, timeout: float = 2.0) -> dict:
    """
    NFS NULL call по TCP (программа 100003, версия 3).
    ФИКС: reader.read() обёрнут в wait_for.
    """
    nfs_null = bytes.fromhex(
        "80000028"
        "87654321"   # XID
        "00000000"
        "00000002"
        "000186a3"   # program: NFS (100003)
        "00000003"   # version: 3
        "00000000"
        "00000000"
        "00000000"
        "00000000"
        "00000000"
    )
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port), timeout=timeout
        )
        writer.write(nfs_null)
        await writer.drain()
        try:
            data = await asyncio.wait_for(reader.read(128), timeout=timeout)
        except asyncio.TimeoutError:
            writer.close()
            return {"status": "open", "vulnerable": True,
                    "banner": "NFS port open (no RPC response)"}
        writer.close()
        await writer.wait_closed()

        xid_match = len(data) >= 8 and data[4:8] == b"\x87\x65\x43\x21"
        return {
            "status": "open",
            "vulnerable": True,
            "banner": "NFS v3 NULL call accepted" if xid_match
                      else f"NFS-like response ({len(data)} bytes)",
        }
    except Exception:
        return {"status": "closed", "vulnerable": False}


# ---------------------------------------------------------------------------
# IRC (порты 6667 / 6697)
# ---------------------------------------------------------------------------

_IRC_VERSION_RE = re.compile(r"(unrealircd|inspircd|ircd)[^\s]*\s*([\d.]+)", re.I)


async def check_irc(host: str, port: int = 6667, timeout: float = 3.0) -> dict:
    """
    IRC: отправляем NICK+USER чтобы спровоцировать ответ сервера.
    ФИКС 1: reader.read() обёрнут в wait_for.
    ФИКС 2: добавлена отправка NICK/USER (без них некоторые IRC-серверы
             не присылают баннер вообще, что давало ложный status=closed).
    """
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port), timeout=timeout
        )
        writer.write(b"NICK perimeter_probe\r\nUSER perimeter 0 * :Perimeter\r\n")
        await writer.drain()

        try:
            data = await asyncio.wait_for(reader.read(1024), timeout=timeout)
        except asyncio.TimeoutError:
            writer.close()
            return {"status": "open", "banner": "IRC open (no response to NICK/USER)",
                    "version": "", "vulnerable": False}

        writer.close()
        await writer.wait_closed()

        banner = data.decode("utf-8", errors="ignore")
        m = _IRC_VERSION_RE.search(banner)
        version = m.group(0) if m else ""
        # UnrealIRCd 3.2.8.1 — известный бэкдор CVE-2010-2075
        backdoor = bool(re.search(r"unrealircd.*3\.2\.8", banner, re.I))
        return {
            "status": "open",
            "banner": banner.strip(),
            "version": version,
            "vulnerable": backdoor,
        }
    except Exception:
        return {"status": "closed", "vulnerable": False}


# ---------------------------------------------------------------------------
# distccd (порт 3632)
# ---------------------------------------------------------------------------

async def check_distccd(host: str, port: int = 3632, timeout: float = 2.0) -> dict:
    """
    Отправляем distcc-magic и читаем ответ.
    ФИКС 1: reader.read() обёрнут в wait_for.
    ФИКС 2: добавлена отправка DIST-пробы (без неё distccd молчит в ответ
             на пустой коннект, и функция давала ложный status=closed).
    """
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port), timeout=timeout
        )
        writer.write(b"DIST00000001")
        await writer.drain()

        try:
            data = await asyncio.wait_for(reader.read(256), timeout=timeout)
        except asyncio.TimeoutError:
            writer.close()
            return {"status": "open", "banner": "distccd open (no protocol response)",
                    "vulnerable": True}

        writer.close()
        await writer.wait_closed()

        banner = data.decode("utf-8", errors="ignore").strip()
        markers = ("DIST", "DONE", "DOTO", "ERR", "distcc")
        confirmed = any(m.lower() in banner.lower() for m in markers)
        return {
            "status": "open",
            "banner": banner or "distccd open",
            # Открытый distccd опасен сам по себе, но подтверждён лишь протокол
            "vulnerable": confirmed,
            "detail": "distccd protocol confirmed" if confirmed else "distccd port open",
        }
    except Exception:
        return {"status": "closed", "vulnerable": False}


# ---------------------------------------------------------------------------
# Bind Shell (порты 1524, 6200)
# ---------------------------------------------------------------------------

async def check_bind_shell(host: str, port: int = 1524, timeout: float = 2.0) -> dict:
    """
    Пассивный детектор bind shell — читает баннер, НЕ выполняет команды.
    Shell-prompt (root@metasploitable:/#) — 100% доказательство бэкдора.
    """
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port), timeout=timeout
        )
        try:
            data = await asyncio.wait_for(reader.read(256), timeout=timeout)
        except asyncio.TimeoutError:
            writer.close()
            return {"status": "open", "banner": "", "vulnerable": False,
                    "detail": "port open, no shell prompt received"}
        writer.close()
        await writer.wait_closed()

        banner = data.decode("utf-8", errors="ignore")
        # Детект shell-промпта: root@host:/# или просто #
        vulnerable = "#" in banner or "root@" in banner or "sh-" in banner
        return {
            "status": "open",
            "banner": banner.strip(),
            "vulnerable": vulnerable,
        }
    except Exception:
        return {"status": "closed", "vulnerable": False}


# ---------------------------------------------------------------------------
# VNC (порт 5900)
# ---------------------------------------------------------------------------

async def check_vnc(host: str, port: int = 5900, timeout: float = 2.0) -> dict:
    """VNC сам присылает RFB-баннер сразу после коннекта."""
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port), timeout=timeout
        )
        data = await asyncio.wait_for(reader.read(32), timeout=timeout)
        writer.close()
        await writer.wait_closed()
        banner = data.decode("ascii", errors="ignore").strip()
        if banner.startswith("RFB "):
            return {"status": "open", "banner": banner, "vulnerable": False,
                    "detail": "VNC protocol confirmed"}
        return {"status": "open", "banner": banner or "no VNC banner",
                "vulnerable": False}
    except Exception:
        return {"status": "closed", "vulnerable": False}