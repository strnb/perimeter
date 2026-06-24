import asyncio
import logging
import os
from datetime import datetime
from typing import List, Dict, Any, Optional, TypedDict

import whois
import dns.resolver

# Настройка логгера для модуля
logger = logging.getLogger(__name__)

class WhoisData(TypedDict):
    registrar: str
    creation_date: str
    expiration_date: str
    name_servers: List[str]

class OSINTReport(TypedDict):
    domain: str
    scan_time: str
    whois: WhoisData
    dns: Dict[str, List[str]]
    subdomains: List[Dict[str, str]]

def _parse_whois_date(date_field: Any) -> str:
    """Безопасно нормализует даты из WHOIS в строку."""
    if isinstance(date_field, list):
        date_field = date_field[0]
    if isinstance(date_field, datetime):
        return date_field.strftime("%Y-%m-%d %H:%M:%S")
    return str(date_field) if date_field else "unknown"

def _sync_whois(domain: str) -> WhoisData:
    """Синхронный воркер для получения WHOIS данных."""
    try:
        w = whois.whois(domain)
        return {
            "registrar": str(w.registrar) if w.registrar else "unknown",
            "creation_date": _parse_whois_date(w.creation_date),
            "expiration_date": _parse_whois_date(w.expiration_date),
            "name_servers": list(w.name_servers) if w.name_servers else []
        }
    except Exception as e:
        logger.debug(f"WHOIS error for {domain}: {e}")
        return {
            "registrar": "unknown",
            "creation_date": "unknown",
            "expiration_date": "unknown",
            "name_servers": []
        }

async def get_whois(domain: str) -> WhoisData:
    """Асинхронная обертка для WHOIS."""
    return await asyncio.to_thread(_sync_whois, domain)

def _sync_dns(domain: str) -> Dict[str, List[str]]:
    """Синхронный воркер для получения DNS-записей."""
    result = {"A": [], "MX": [], "TXT": []}
    resolver = dns.resolver.Resolver()
    resolver.timeout = 2.0
    resolver.lifetime = 2.0

    for rtype in result.keys():
        try:
            answers = resolver.resolve(domain, rtype)
            for rdata in answers:
                if rtype == "A":
                    result["A"].append(str(rdata.address))
                elif rtype == "MX":
                    result["MX"].append(f"{rdata.preference} {str(rdata.exchange).rstrip('.')}")
                elif rtype == "TXT":
                    txt_strings = [b.decode('utf-8', errors='ignore') for b in rdata.strings]
                    result["TXT"].append(" ".join(txt_strings))
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers):
            continue
        except Exception as e:
            logger.debug(f"DNS error for {domain} type {rtype}: {e}")
    return result

async def get_dns(domain: str) -> Dict[str, List[str]]:
    """Асинхронная обертка для DNS-запросов."""
    return await asyncio.to_thread(_sync_dns, domain)

async def _resolve_subdomain(subdomain_full: str, semaphore: asyncio.Semaphore) -> Optional[Dict[str, str]]:
    """Пытается разрешить один поддомен с ограничением конкурентности."""
    async with semaphore:
        try:
            # Используем системный резолвер через thread pool
            answers = await asyncio.to_thread(dns.resolver.resolve, subdomain_full, "A")
            if answers:
                return {"subdomain": subdomain_full, "ip": str(answers[0].address)}
        except Exception:
            return None
    return None

async def find_subdomains(domain: str, wordlist_path: str = "core/subdomains_wordlist.txt") -> List[Dict[str, str]]:
    """Асинхронный брутфорс поддоменов."""
    if not os.path.exists(wordlist_path):
        logger.error(f"Wordlist not found: {wordlist_path}")
        return []

    with open(wordlist_path, "r", encoding="utf-8") as f:
        sub_prefixes = [line.strip() for line in f if line.strip()]

    semaphore = asyncio.Semaphore(50)
    tasks = [
        _resolve_subdomain(f"{sub}.{domain}", semaphore) 
        for sub in sub_prefixes
    ]

    logger.info(f"Starting subdomain brute for {domain} ({len(tasks)} tasks)")
    results = await asyncio.gather(*tasks)
    return [res for res in results if res]

async def run_osint(domain: str, wordlist_path: str = "core/subdomains_wordlist.txt") -> OSINTReport:
    """Комплексный OSINT-анализ домена."""
    logger.info(f"Starting OSINT analysis for: {domain}")

    # Запускаем WHOIS и DNS параллельно, так как они независимы
    whois_task = get_whois(domain)
    dns_task = get_dns(domain)
    
    whois_data, dns_data = await asyncio.gather(whois_task, dns_task)
    subdomain_data = await find_subdomains(domain, wordlist_path)

    report: OSINTReport = {
        "domain": domain,
        "scan_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "whois": whois_data,
        "dns": dns_data,
        "subdomains": subdomain_data
    }

    logger.info(f"OSINT analysis for {domain} completed.")
    return report
