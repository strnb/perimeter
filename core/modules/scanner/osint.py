"""OSINT: WHOIS, DNS, поддомены (crt.sh + wordlist), проверки конфигурации.

Модуль пассивный по умолчанию: WHOIS, DNS, Certificate Transparency и
wordlist. Активные действия (AXFR, HTTP-пробы) включаются флагом active.

Каждый внешний источник изолирован: его сбой попадает в sources/error и не
роняет остальной отчёт.
"""

import asyncio
import json
import logging
import os
import re
import time
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, TypedDict
from urllib.parse import urlsplit
from uuid import uuid4

import dns.asyncresolver
import dns.exception
import dns.query
import dns.resolver
import dns.zone
import httpx
import whois

from core.paths import app_data_dir, resource_path
from . import osint_checks as checks

logger = logging.getLogger(__name__)

_DEFAULT_WORDLIST = str(resource_path("core/subdomains_wordlist.txt"))

# Внешний словарь можно указать флагом --wordlist или переменной окружения.
# SecLists/Assetnote ставятся отдельно и дают на порядок больше покрытия.
WORDLIST_ENV = "PERIMETER_WORDLIST"
WORDLIST_CANDIDATES = (
    "/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt",
    "/usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt",
    "/usr/share/seclists/Discovery/DNS/dns-Jhaddix.txt",
    "/usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt",
    "/opt/seclists/Discovery/DNS/subdomains-top1million-5000.txt",
    "/opt/homebrew/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt",
)


def default_wordlist() -> str:
    """Встроенный словарь или установленный внешний (env -> известные пути)."""
    env_path = os.environ.get(WORDLIST_ENV)
    if env_path and os.path.exists(env_path):
        return env_path
    for candidate in WORDLIST_CANDIDATES:
        if os.path.exists(candidate):
            return candidate
    return _DEFAULT_WORDLIST
CACHE_TTL_HOURS = 24
SUBDOMAIN_LIMIT = 20000
CRTSH_LIMIT = 5000
CRTSH_TIMEOUT = 45.0
CRTSH_ATTEMPTS = 2
HTTP_TIMEOUT = 5.0
# Тело нужно только для <title> и признаков takeover: больше не читаем
MAX_BODY_BYTES = 200_000
# Активная HTTP-проба всех имён из crt.sh — это тысячи запросов к чужим серверам
MAX_HTTP_PROBES = 200
USER_AGENT = "perimeter-osint/1.0 (+https://github.com/strnb/perimeter)"

DNS_TYPES = ("A", "AAAA", "MX", "TXT", "NS", "SOA", "CNAME", "CAA", "DS")
DKIM_SELECTORS = ("default", "google", "selector1", "selector2", "k1", "mail", "s1", "s2", "dkim")


class WhoisData(TypedDict, total=False):
    registrar: str
    registrant_org: str
    creation_date: str
    expiration_date: str
    updated_date: str
    age_days: Optional[int]
    expires_in_days: Optional[int]
    status: List[str]
    name_servers: List[str]
    error: Optional[str]


class OSINTReport(TypedDict, total=False):
    domain: str
    scan_time: str
    duration_sec: float
    sources: Dict[str, str]
    whois: WhoisData
    dns: Dict[str, List[str]]
    email: Dict[str, Any]
    security: Dict[str, Any]
    subdomains: List[Dict[str, Any]]
    findings: List[Dict[str, str]]
    cached: bool
    cache_age_hours: Optional[float]


# ---------------------------------------------------------------------------
# Домен
# ---------------------------------------------------------------------------

_LABEL_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")


def normalize_domain(raw: str) -> str:
    """Приводит ввод к чистому домену или бросает ValueError.

    Принимает URL, путь, порт, верхний регистр, IDN и точку в конце.
    """
    value = (raw or "").strip().lower()
    if not value:
        raise ValueError("домен не указан")

    if "://" in value:
        value = urlsplit(value).hostname or ""
    else:
        value = value.split("/")[0].split("?")[0].split("#")[0]
        # порт отрезаем только у последнего сегмента (IPv6 в квадратных скобках не поддержан)
        if value.count(":") == 1:
            value = value.split(":")[0]

    value = value.rstrip(".")
    # www.example.com для разведки домена — это тот же example.com
    if value.startswith("www."):
        value = value[4:]

    try:
        value = value.encode("idna").decode("ascii")
    except UnicodeError:
        raise ValueError(f"не удалось преобразовать домен: {raw}")

    if len(value) > 253:
        raise ValueError("домен длиннее 253 символов")

    labels = value.split(".")
    if len(labels) < 2:
        raise ValueError(f"это не домен: {raw}")
    if not all(_LABEL_RE.match(label) for label in labels):
        raise ValueError(f"недопустимые символы в домене: {raw}")
    if labels[-1].isdigit() or len(labels[-1]) < 2:
        raise ValueError(f"недопустимая доменная зона: {raw}")

    return value


# ---------------------------------------------------------------------------
# DNS
# ---------------------------------------------------------------------------

class DNSClient:
    """Тонкая обёртка над dnspython: только нужные типы и без исключений."""

    def __init__(self, timeout: float = 3.0):
        self.resolver = dns.asyncresolver.Resolver()
        self.resolver.timeout = timeout
        self.resolver.lifetime = timeout

    async def query_status(self, name: str, rtype: str) -> tuple[list, bool]:
        """(records, имя_существует). NXDOMAIN — имени нет вообще.

        Один повтор только на сбоях резолвера: при таймауте иначе теряется
        существующее имя, а при NODATA повтор бессмыслен.
        """
        for attempt in range(2):
            try:
                answer = await self.resolver.resolve(name, rtype, raise_on_no_answer=False)
            except dns.resolver.NXDOMAIN:
                return [], False
            except (dns.resolver.NoNameservers, dns.exception.Timeout):
                if attempt == 0:
                    continue
                return [], True
            except dns.exception.DNSException:
                return [], True
            except Exception as exc:
                logger.debug("DNS %s %s: %s", name, rtype, exc)
                return [], True

            if answer.rrset is None:
                return [], True
            return list(answer), True

        return [], True

    async def query(self, name: str, rtype: str) -> list:
        records, _exists = await self.query_status(name, rtype)
        return records


def _text(value) -> str:
    return value.decode("utf-8", "ignore") if isinstance(value, bytes) else str(value)


def _format_rdata(rtype: str, rdata) -> str:
    if rtype in ("A", "AAAA"):
        return str(rdata.address)
    if rtype == "MX":
        exchange = str(rdata.exchange)
        return f"{rdata.preference} {exchange.rstrip('.') or '.'}"
    if rtype == "TXT":
        parts = getattr(rdata, "strings", None)
        if parts:
            return " ".join(_text(part) for part in parts)
        return _text(rdata.to_text()).strip('"')
    if rtype == "SOA":
        return f"{str(rdata.mname).rstrip('.')} {str(rdata.rname).rstrip('.')} {rdata.serial}"
    if rtype in ("NS", "CNAME", "PTR"):
        return str(getattr(rdata, "target", rdata)).rstrip(".")
    if rtype == "CAA":
        return f'{rdata.flags} {_text(rdata.tag)} "{_text(rdata.value)}"'
    return _text(rdata.to_text())


async def get_dns(domain: str, dns_client=None) -> Dict[str, List[str]]:
    """Все записи одним проходом; пустые типы остаются пустыми списками."""
    client = dns_client or DNSClient()
    answers = await asyncio.gather(*(client.query(domain, rtype) for rtype in DNS_TYPES))
    return {
        rtype: [_format_rdata(rtype, rdata) for rdata in records]
        for rtype, records in zip(DNS_TYPES, answers)
    }


async def get_dmarc(domain: str, dns_client=None) -> List[str]:
    client = dns_client or DNSClient()
    records = await client.query(f"_dmarc.{domain}", "TXT")
    return [_format_rdata("TXT", rdata) for rdata in records]


async def get_dkim(domain: str, dns_client=None) -> List[str]:
    """Какие из частых селекторов DKIM реально опубликованы.

    Запись с пустым p= означает «ключ отозван» — это не найденный DKIM.
    """
    client = dns_client or DNSClient()

    async def one(selector):
        name = f"{selector}._domainkey.{domain}"
        records = await client.query(name, "TXT")
        for record in records:
            text = _format_rdata("TXT", record)
            match = re.search(r"\bp\s*=\s*([^;\s]+)", text, re.I)
            if match and match.group(1).strip():
                return selector
        return None

    found = await asyncio.gather(*(one(selector) for selector in DKIM_SELECTORS))
    return [selector for selector in found if selector]


# ---------------------------------------------------------------------------
# WHOIS
# ---------------------------------------------------------------------------

def _as_datetime(value) -> Optional[datetime]:
    if isinstance(value, list):
        value = value[0] if value else None
    if isinstance(value, datetime):
        return value
    if isinstance(value, str):
        for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d", "%d.%m.%Y"):
            try:
                return datetime.strptime(value.strip()[:19], fmt)
            except ValueError:
                continue
    return None


def _fmt_date(value) -> str:
    parsed = _as_datetime(value)
    return parsed.strftime("%Y-%m-%d") if parsed else "unknown"


def _days_until(moment: Optional[datetime]) -> Optional[int]:
    if moment is None:
        return None
    now = datetime.now(moment.tzinfo) if moment.tzinfo else datetime.now()
    return (moment - now).days


def _days_since(moment: Optional[datetime]) -> Optional[int]:
    if moment is None:
        return None
    now = datetime.now(moment.tzinfo) if moment.tzinfo else datetime.now()
    return (now - moment).days


def _whois_snapshot(raw) -> WhoisData:
    expiration = _as_datetime(raw.expiration_date)
    creation = _as_datetime(raw.creation_date)
    servers = raw.name_servers or []
    if isinstance(servers, str):
        servers = [servers]
    status = raw.status or []
    if isinstance(status, str):
        status = [status]

    return {
        "registrar": str(raw.registrar) if raw.registrar else "unknown",
        "registrant_org": str(getattr(raw, "org", None) or "unknown"),
        "creation_date": _fmt_date(creation),
        "expiration_date": _fmt_date(expiration),
        "updated_date": _fmt_date(raw.updated_date),
        "age_days": _days_since(creation),
        "expires_in_days": _days_until(expiration),
        "status": [str(item) for item in status][:10],
        "name_servers": sorted({str(server).lower().rstrip(".") for server in servers}),
        "error": None,
    }


async def get_whois(domain: str, whois_func=None) -> WhoisData:
    func = whois_func or whois.whois
    try:
        raw = await asyncio.wait_for(asyncio.to_thread(func, domain), timeout=30)
    except asyncio.TimeoutError:
        return {"registrar": "unknown", "error": "таймаут WHOIS"}
    except Exception as exc:
        logger.debug("WHOIS %s: %s", domain, exc)
        return {"registrar": "unknown", "error": str(exc)[:200]}
    return _whois_snapshot(raw)


# ---------------------------------------------------------------------------
# Поддомены: crt.sh, hackertarget, wordlist
# ---------------------------------------------------------------------------

async def get_crtsh(domain: str, client: httpx.AsyncClient) -> tuple[List[str], str]:
    """Поддомены из Certificate Transparency. Возвращает (имена, статус).

    crt.sh отвечает медленно (до 30–40 с) и периодически отдаёт 502,
    поэтому один повтор — часть нормальной работы, а не костыль.
    """
    status = "crt.sh: нет ответа"
    for attempt in range(CRTSH_ATTEMPTS):
        if attempt:
            await asyncio.sleep(2)

        try:
            response = await client.get(
                "https://crt.sh/",
                params={"q": f"%.{domain}", "output": "json"},
                timeout=httpx.Timeout(CRTSH_TIMEOUT, connect=10.0),
            )
        except Exception as exc:
            status = f"crt.sh: {type(exc).__name__}"
            continue

        if response.status_code != 200:
            status = f"crt.sh: HTTP {response.status_code}"
            continue

        try:
            rows = response.json()
        except ValueError:
            status = "crt.sh: некорректный JSON"
            continue

        if not isinstance(rows, list):
            status = "crt.sh: неожиданный формат ответа"
            continue

        names = set()
        for row in rows:
            if not isinstance(row, dict):
                continue
            for field in ("name_value", "common_name"):
                for line in str(row.get(field) or "").splitlines():
                    name = line.strip().lower().rstrip(".")
                    if name.startswith("*."):
                        name = name[2:]
                    if name.endswith("." + domain) and name != domain:
                        names.add(name)

        found = sorted(names)[:CRTSH_LIMIT]
        return found, f"crt.sh: {len(found)}"

    return [], status


async def get_hackertarget(domain: str, client: httpx.AsyncClient) -> tuple[List[str], str]:
    """Бесплатный hostsearch. Лимит около 100 запросов в сутки."""
    try:
        response = await client.get(
            "https://api.hackertarget.com/hostsearch/",
            params={"q": domain},
            timeout=httpx.Timeout(20.0, connect=10.0),
        )
    except Exception as exc:
        return [], f"hackertarget: {type(exc).__name__}"

    if response.status_code != 200:
        return [], f"hackertarget: HTTP {response.status_code}"

    names = set()
    for line in response.text.splitlines():
        if "," not in line:
            continue
        host = line.split(",", 1)[0].strip().lower().rstrip(".")
        if host.endswith("." + domain) and host != domain:
            names.add(host)

    if not names and response.text.strip() and "error" in response.text.lower():
        return [], "hackertarget: отказ API (лимит?)"

    found = sorted(names)
    return found, f"hackertarget: {len(found)}"


def _read_wordlist(path: str) -> List[str]:
    if not os.path.exists(path):
        logger.error("Wordlist not found: %s", path)
        return []
    # utf-8-sig: файлы, сохранённые в Windows, часто начинаются с BOM,
    # иначе первый поддомен в списке молча теряется
    with open(path, "r", encoding="utf-8-sig", errors="ignore") as handle:
        prefixes = [line.strip().lower() for line in handle]
    # только валидные DNS-label: мусорные строки не должны тратить запросы
    return [prefix for prefix in prefixes
            if prefix and prefix[0] != "#" and _LABEL_RE.match(prefix)]


async def _resolve_host(name: str, dns_client, semaphore: asyncio.Semaphore) -> Optional[Dict[str, Any]]:
    async with semaphore:
        a_records, exists = await dns_client.query_status(name, "A")
        if not exists:
            return None  # NXDOMAIN: остальные типы спрашивать бессмысленно

        ips = [str(rdata.address) for rdata in a_records]

        # CNAME спрашиваем и при наличии A: висячий CNAME на CDN/S3 — основной
        # случай takeover, а его A-запись резолвится на стороне провайдера.
        cname_task = dns_client.query(name, "CNAME")
        if ips:
            cname_records = await cname_task
        else:
            # AAAA и CNAME параллельно: у промахов это половина времени скана
            aaaa_records, cname_records = await asyncio.gather(
                dns_client.query(name, "AAAA"),
                cname_task,
            )
            ips = [str(rdata.address) for rdata in aaaa_records]

        cname = _format_rdata("CNAME", cname_records[0]) if cname_records else None

        if not ips and not cname:
            return None

        return {
            "subdomain": name,
            "ip": ips[0] if ips else None,
            "ips": ips,
            "cname": cname,
        }


async def find_subdomains(
    domain: str,
    wordlist_path: Optional[str] = None,
    *,
    dns_client=None,
    names: Optional[List[str]] = None,
    concurrency: int = 50,
    use_wordlist: bool = True,
) -> List[Dict[str, Any]]:
    """Резолвит имена из wordlist и пассивных источников.

    names — уже собранные имена (crt.sh, hackertarget); они считаются
    доказанными и не отбрасываются wildcard-фильтром.
    """
    client = dns_client or DNSClient()
    semaphore = asyncio.Semaphore(max(1, concurrency))

    proven = {name.lower() for name in (names or [])}
    prefixes = _read_wordlist(wordlist_path or default_wordlist()) if use_wordlist else []
    candidates = {f"{prefix}.{domain}" for prefix in prefixes} | proven
    # доказанные имена резолвим первыми, если упрёмся в лимит
    ordered = sorted(proven) + sorted(candidates - proven)
    if len(ordered) > SUBDOMAIN_LIMIT:
        logger.warning("%s: %d имён, проверяются первые %d (лимит)",
                       domain, len(ordered), SUBDOMAIN_LIMIT)
    candidates = ordered[:SUBDOMAIN_LIMIT]

    # Wildcard: два случайных имени. Если отвечают — зона отдаёт всё подряд.
    wildcard_ips = set()
    for _ in range(2):
        probe = f"perimeter-wildcard-{uuid4().hex[:10]}.{domain}"
        result = await _resolve_host(probe, client, semaphore)
        if result:
            wildcard_ips.update(result["ips"])

    results = await asyncio.gather(
        *(_resolve_host(name, client, semaphore) for name in candidates)
    )

    found = []
    for result in results:
        if not result:
            continue

        if wildcard_ips and result["subdomain"] not in proven:
            if result["ips"] and set(result["ips"]) <= wildcard_ips:
                continue

        result["source"] = "passive" if result["subdomain"] in proven else "wordlist"
        found.append(result)

    if wildcard_ips:
        logger.warning("%s: wildcard DNS, шум отфильтрован", domain)

    return found


# ---------------------------------------------------------------------------
# Активные проверки
# ---------------------------------------------------------------------------

async def try_zone_transfer(domain: str, name_servers: List[str]) -> str:
    """Пробует AXFR по каждому NS. Возвращает статус для отчёта."""

    def attempt(ns: str):
        zone = dns.zone.from_xfr(dns.query.xfr(ns, domain, timeout=5))
        return zone is not None

    for ns in name_servers:
        try:
            if await asyncio.wait_for(asyncio.to_thread(attempt, ns), timeout=10):
                return f"VULNERABLE: {ns}"
        except Exception as exc:
            logger.debug("AXFR %s: %s", ns, exc)

    return "failed"


def _tls_info(response) -> Dict[str, Any]:
    """Данные сертификата из уже открытого соединения httpx."""
    try:
        stream = response.extensions.get("network_stream")
        ssl_object = stream.get_extra_info("ssl_object") if stream else None
        if ssl_object is None:
            return {}
        der = ssl_object.getpeercert(binary_form=True)
        if not der:
            return {}

        from cryptography import x509
        certificate = x509.load_der_x509_certificate(der)
        expiry = getattr(certificate, "not_valid_after_utc", None)
        if expiry is None:
            expiry = certificate.not_valid_after
        now = datetime.now(expiry.tzinfo) if expiry.tzinfo else datetime.now()
        return {
            "tls_expires": expiry.strftime("%Y-%m-%d"),
            "tls_days_left": (expiry - now).days,
            "tls_issuer": certificate.issuer.rfc4514_string()[:120],
        }
    except Exception:
        return {}


def _page_title(html: str) -> str:
    match = re.search(r"<title[^>]*>(.*?)</title>", html[:50000], re.I | re.S)
    if not match:
        return ""
    return " ".join(match.group(1).split())[:80]


async def probe_http(name: str, client: httpx.AsyncClient, semaphore: asyncio.Semaphore) -> Optional[Dict[str, Any]]:
    """Пробует https, затем http. Возвращает статус, заголовок и TLS.

    Тело читается потоком и обрезается: иначе чужой файл на 500 МБ
    съест память при скане поддоменов.
    """
    async with semaphore:
        for scheme in ("https", "http"):
            try:
                async with client.stream("GET", f"{scheme}://{name}",
                                         timeout=HTTP_TIMEOUT) as response:
                    chunks = []
                    total = 0
                    async for chunk in response.aiter_bytes():
                        chunks.append(chunk)
                        total += len(chunk)
                        if total >= MAX_BODY_BYTES:
                            break

                    body = b"".join(chunks)[:MAX_BODY_BYTES].decode("utf-8", "ignore")
                    info = {
                        "url": str(response.url),
                        "status": response.status_code,
                        "title": _page_title(body),
                        "server": response.headers.get("server", "")[:60],
                    }
                    info.update(_tls_info(response))
                    info["body"] = body
                    return info
            except Exception:
                continue

    return None


async def _http_inventory(subdomains: List[Dict[str, Any]], client: httpx.AsyncClient) -> None:
    semaphore = asyncio.Semaphore(20)

    probed = subdomains[:MAX_HTTP_PROBES]
    if len(subdomains) > len(probed):
        logger.warning("HTTP-проба: проверяются первые %d из %d имён (лимит)",
                       len(probed), len(subdomains))

    async def one(sub):
        info = await probe_http(sub["subdomain"], client, semaphore)
        if info is None:
            return
        body = info.pop("body", "")
        sub["http"] = info
        sub["takeover"] = checks.is_takeover_candidate(sub.get("cname"), info["status"], body)

    await asyncio.gather(*(one(sub) for sub in probed))


# ---------------------------------------------------------------------------
# Кэш
# ---------------------------------------------------------------------------

def _cache_file(domain: str, cache_dir) -> Path:
    base = Path(cache_dir) if cache_dir else app_data_dir() / "cache" / "osint"
    base.mkdir(parents=True, exist_ok=True)
    return base / f"{domain}.json"


def _cache_key(wordlist_path: Optional[str]) -> str:
    path = wordlist_path or default_wordlist()
    try:
        return f"{os.path.abspath(path)}:{os.path.getsize(path)}"
    except OSError:
        return os.path.abspath(path)


def _read_cache(path: Path, domain: str, sources: List[str], active: bool,
                wordlist_key: str) -> Optional[dict]:
    if not path.exists():
        return None
    try:
        report = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None

    meta = report.get("_cache") or {}
    if report.get("domain") != domain or meta.get("active") != active:
        return None
    if meta.get("sources") != sorted(sources):
        return None
    if meta.get("wordlist") != wordlist_key:
        return None

    age_hours = (time.time() - float(meta.get("ts", 0))) / 3600
    if age_hours > CACHE_TTL_HOURS:
        return None

    report.pop("_cache", None)
    report["cached"] = True
    report["cache_age_hours"] = round(age_hours, 1)
    return report


def _write_cache(path: Path, report: dict, sources: List[str], active: bool,
                 wordlist_key: str) -> None:
    payload = dict(report)
    payload["_cache"] = {
        "ts": time.time(),
        "sources": sorted(sources),
        "active": active,
        "wordlist": wordlist_key,
    }
    try:
        path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    except OSError as exc:
        logger.debug("cache write %s: %s", path, exc)


# ---------------------------------------------------------------------------
# Главный сценарий
# ---------------------------------------------------------------------------

def _whois_findings(whois_data: WhoisData) -> List[dict]:
    findings = []
    expires = whois_data.get("expires_in_days")
    if isinstance(expires, int) and expires <= 60:
        severity = "high" if expires <= 14 else "medium"
        findings.append({
            "kb_id": "VULN-049",
            "type": "domain_expiring",
            "severity": severity,
            "title": "Срок регистрации домена истекает",
            "detail": f"Домен истекает {whois_data.get('expiration_date')} (через {expires} дн.).",
            "fix": "Продлить регистрацию и включить автопродление у регистратора.",
        })
    return findings


async def run_osint(
    domain: str,
    wordlist_path: Optional[str] = None,
    *,
    active: bool = False,
    sources: Optional[List[str]] = None,
    concurrency: int = 50,
    use_cache: bool = True,
    cache_dir=None,
    dns_client=None,
    http_client: Optional[httpx.AsyncClient] = None,
    whois_func=None,
    axfr_func=None,
) -> OSINTReport:
    """Полный OSINT-отчёт по домену. Ошибки источников — в отчёте, не в исключении."""
    started = time.perf_counter()
    clean_domain = normalize_domain(domain)
    sources = sources or ["crt", "wordlist"]
    source_names = sorted(set(sources))

    cache_path = _cache_file(clean_domain, cache_dir) if use_cache else None
    wordlist_key = _cache_key(wordlist_path)
    if cache_path:
        cached = _read_cache(cache_path, clean_domain, source_names, active, wordlist_key)
        if cached:
            return cached

    own_client = http_client is None
    client = http_client or httpx.AsyncClient(
        verify=False,
        follow_redirects=True,
        headers={"User-Agent": USER_AGENT},
    )
    # crt.sh/hackertarget — доверенные API: сертификат проверяем. Отдельный
    # клиент нужен, потому что пробы целей идут с verify=False.
    api_client = http_client or httpx.AsyncClient(
        follow_redirects=True,
        headers={"User-Agent": USER_AGENT},
    )
    dns_client = dns_client or DNSClient()

    sources_status: Dict[str, str] = {}
    findings: List[dict] = []

    try:
        whois_data, dns_data = await asyncio.gather(
            get_whois(clean_domain, whois_func=whois_func),
            get_dns(clean_domain, dns_client=dns_client),
        )
        sources_status["whois"] = "error: " + whois_data["error"] if whois_data.get("error") else "ok"
        sources_status["dns"] = "ok" if any(dns_data.values()) else "error: нет ответов"

        if not any(dns_data.values()) and whois_data.get("error"):
            raise ValueError(
                f"домен {clean_domain} не резолвится и WHOIS недоступен — проверьте имя"
            )

        dmarc_records, dkim_found = await asyncio.gather(
            get_dmarc(clean_domain, dns_client=dns_client),
            get_dkim(clean_domain, dns_client=dns_client),
        )

        passive_names: List[str] = []
        if "crt" in sources:
            names, status = await get_crtsh(clean_domain, api_client)
            passive_names += names
            sources_status["crt.sh"] = status
        if "hackertarget" in sources:
            names, status = await get_hackertarget(clean_domain, api_client)
            passive_names += names
            sources_status["hackertarget"] = status

        subdomains = await find_subdomains(
            clean_domain,
            wordlist_path,
            dns_client=dns_client,
            names=passive_names,
            concurrency=concurrency,
            use_wordlist="wordlist" in sources,
        )
        sources_status["wordlist"] = "ok" if "wordlist" in sources else "отключён"
        zone_transfer = "not_checked"
        if active:
            name_servers = dns_data.get("NS", [])
            if name_servers:
                zone_transfer = await (axfr_func or try_zone_transfer)(clean_domain, name_servers)
            await _http_inventory(subdomains, client)

        email_data, email_findings = checks.analyze_spf(dns_data.get("TXT", []))
        dmarc_data, dmarc_findings = checks.analyze_dmarc(dmarc_records)
        security_data, security_findings = checks.analyze_security(
            dns_data.get("DS", []), dns_data.get("CAA", []), zone_transfer
        )

        findings += email_findings + dmarc_findings + security_findings
        findings += _whois_findings(whois_data)
        findings += checks.analyze_http(subdomains)
    finally:
        if own_client:
            await client.aclose()
            await api_client.aclose()

    order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    findings.sort(key=lambda item: order.get(item["severity"], 9))

    report: OSINTReport = {
        "domain": clean_domain,
        "scan_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "duration_sec": round(time.perf_counter() - started, 2),
        "sources": sources_status,
        "whois": whois_data,
        "dns": dns_data,
        "email": {
            "spf": email_data,
            "dmarc": dmarc_data,
            "dkim": dkim_found,
        },
        "security": security_data,
        "subdomains": subdomains,
        "findings": findings,
        "cached": False,
    }

    if cache_path:
        _write_cache(cache_path, report, source_names, active, wordlist_key)

    return report
