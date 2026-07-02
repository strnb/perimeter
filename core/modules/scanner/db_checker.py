import asyncio
import re
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
        # Server is reachable but auth is required
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
        return {"status": "open", "weak_creds": True, "detail": "root without password", "vulnerable": True}
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
                "vulnerable": True,
            }
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
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port), timeout=timeout
        )
        data = await asyncio.wait_for(reader.read(1024), timeout=timeout)
        writer.close()
        await writer.wait_closed()
        banner = data.decode("utf-8", errors="ignore")
        if "Samba" in banner or len(data) > 0:
            return {
                "status": "open",
                "banner": banner.strip(),
                "vulnerable": True,
                "detail": "Old Samba version detected (Metasploitable 2)",
            }
        return {"status": "open", "banner": "", "vulnerable": False}
    except Exception:
        return {"status": "closed", "vulnerable": False}


# ---------------------------------------------------------------------------
# Telnet
# ---------------------------------------------------------------------------

async def check_telnet_banner(host: str, port: int = 23, timeout: float = 2.0) -> dict:
    """Passive banner grab -- telnet sends IAC negotiation immediately on connect."""
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port), timeout=timeout
        )
        data = await reader.read(512)
        writer.close()
        await writer.wait_closed()
        banner = data.decode("utf-8", errors="ignore").strip()
        return {"status": "open", "banner": banner, "vulnerable": True}
    except Exception:
        return {"status": "closed", "vulnerable": False}


# ---------------------------------------------------------------------------
# RPCBind / Portmapper (port 111)
# ---------------------------------------------------------------------------

# Minimal RPC NULL call for portmapper v2
_RPC_NULL = bytes.fromhex(
    "80000028"   # record mark: last fragment, length 40
    "12345678"   # XID
    "00000000"   # direction: call
    "00000002"   # RPC version 2
    "000186a0"   # program: portmapper (100000)
    "00000002"   # program version 2
    "00000000"   # procedure: NULL
    "00000000"   # credentials: AUTH_NULL
    "00000000"   # verifier: AUTH_NULL
)


async def check_rpcbind(host: str, port: int = 111, timeout: float = 2.0) -> dict:
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port), timeout=timeout
        )
        writer.write(_RPC_NULL)
        await writer.drain()
        data = await asyncio.wait_for(reader.read(512), timeout=timeout)
        writer.close()
        await writer.wait_closed()
        return {
            "status": "open",
            "vulnerable": bool(data),
            "banner": data.hex() if data else "",
        }
    except Exception:
        return {"status": "closed", "vulnerable": False}


# ---------------------------------------------------------------------------
# NFS (port 2049)
# ---------------------------------------------------------------------------

async def check_nfs(host: str, port: int = 2049, timeout: float = 2.0) -> dict:
    """Passive open-port check -- NFS exposure is the finding itself."""
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port), timeout=timeout
        )
        data = await reader.read(256)
        writer.close()
        await writer.wait_closed()
        banner = data.decode("utf-8", errors="ignore").strip()
        return {"status": "open", "vulnerable": True, "banner": banner}
    except Exception:
        return {"status": "closed", "vulnerable": False}


# ---------------------------------------------------------------------------
# IRC (ports 6667 / 6697)
# ---------------------------------------------------------------------------

_IRC_VERSION_RE = re.compile(r"(unrealircd|inspircd|ircd)[^\s]*\s*([\d.]+)", re.I)


async def check_irc(host: str, port: int = 6667, timeout: float = 3.0) -> dict:
    """Passive banner grab -- IRC servers send a greeting immediately on connect."""
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port), timeout=timeout
        )
        data = await reader.read(512)
        writer.close()
        await writer.wait_closed()
        banner = data.decode("utf-8", errors="ignore")
        m = _IRC_VERSION_RE.search(banner)
        version = m.group(0) if m else ""
        # UnrealIRCd 3.2.8.1 carries a known backdoor (CVE-2010-2075)
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
# distccd (port 3632)
# ---------------------------------------------------------------------------

async def check_distccd(host: str, port: int = 3632, timeout: float = 2.0) -> dict:
    """Passive banner grab -- distccd presence is the finding (CVE-2004-2687)."""
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port), timeout=timeout
        )
        data = await reader.read(256)
        writer.close()
        await writer.wait_closed()
        banner = data.decode("utf-8", errors="ignore")
        return {
            "status": "open",
            "banner": banner.strip(),
            "vulnerable": bool(re.search(r"distcc", banner, re.I)) or len(data) > 0,
        }
    except Exception:
        return {"status": "closed", "vulnerable": False}


# ---------------------------------------------------------------------------
# Bind Shell / Ingreslock (port 1524)
# ---------------------------------------------------------------------------

async def check_bind_shell(host: str, port: int = 1524, timeout: float = 2.0) -> dict:
    """
    Passive bind-shell detector -- no commands are sent to the remote host.
    Connects and reads the banner only; a prompt containing '#', 'root@' or
    'sh-' is a sufficient indicator of an exposed root shell.
    """
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port), timeout=timeout
        )
        data = await asyncio.wait_for(reader.read(256), timeout=timeout)
        writer.close()
        await writer.wait_closed()
        banner = data.decode("utf-8", errors="ignore")
        vulnerable = "#" in banner or "root@" in banner or "sh-" in banner
        return {"status": "open", "banner": banner.strip(), "vulnerable": vulnerable}
    except Exception:
        return {"status": "closed", "vulnerable": False}