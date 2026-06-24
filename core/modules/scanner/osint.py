import asyncio
import logging
import os
import whois
import dns.resolver
from datetime import datetime

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")


# === Задача 14: WHOIS ===
def _sync_whois(domain: str) -> dict:
    """Синхронный воркер для python-whois."""
    try:
        w = whois.whois(domain)

        # В WHOIS даты могут возвращаться как списком (если апдейтов было много), так и одной строкой/datetime.
        # Пишем безопасный нормализатор дат в строку:
        def parse_date(date_field):
            if isinstance(date_field, list):
                date_field = date_field[0]
            if isinstance(date_field, datetime):
                return date_field.strftime("%Y-%m-%d %H:%M:%S")
            return str(date_field) if date_field else "unknown"

        return {
            "registrar": str(w.registrar) if w.registrar else "unknown",
            "creation_date": parse_date(w.creation_date),
            "expiration_date": parse_date(w.expiration_date),
            "name_servers": list(w.name_servers) if w.name_servers else []
        }
    except Exception as e:
        logging.debug(f"[-] WHOIS ошибка для {domain}: {e}")
        return {
            "registrar": "unknown",
            "creation_date": "unknown",
            "expiration_date": "unknown",
            "name_servers": []
        }


async def get_whois(domain: str) -> dict:
    """Асинхронная обертка для WHOIS."""
    return await asyncio.to_thread(_sync_whois, domain)


# === Задача 15: DNS-записи ===
def _sync_dns(domain: str) -> dict:
    """Синхронный воркер для dnspython."""
    result = {"A": [], "MX": [], "TXT": []}
    types = ["A", "MX", "TXT"]

    # Создаем кастомный резолвер, чтобы управлять таймаутами
    resolver = dns.resolver.Resolver()
    resolver.timeout = 2.0
    resolver.lifetime = 2.0

    for rtype in types:
        try:
            answers = resolver.resolve(domain, rtype)
            for rdata in answers:
                if rtype == "A":
                    result["A"].append(str(rdata.address))
                elif rtype == "MX":
                    # У MX записей есть приоритет (preference) и сам хост (exchange)
                    result["MX"].append(f"{rdata.preference} {str(rdata.exchange).rstrip('.')}")
                elif rtype == "TXT":
                    # TXT записи возвращаются в виде байтовых строк в списке
                    txt_strings = [b.decode('utf-8', errors='ignore') for b in rdata.strings]
                    result["TXT"].append(" ".join(txt_strings))
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers):
            continue  # Если записи такого типа нет, просто идем дальше
        except Exception as e:
            logging.debug(f"[-] DNS ошибка для {domain} тип {rtype}: {e}")
            continue

    return result


async def get_dns(domain: str) -> dict:
    """Асинхронная обертка для DNS-запросов."""
    return await asyncio.to_thread(_sync_dns, domain)


# === Задача 16: Асинхронный поиск поддоменов (Brute Force) ===
async def _resolve_subdomain(subdomain_full: str, semaphore: asyncio.Semaphore) -> dict | None:
    """Пытается отрезолвить один поддомен."""
    async with semaphore:
        try:
            # Используем asyncio.to_thread для блокирующей функции DNS
            loop = asyncio.get_event_loop()
            # Нативный резолвер операционной системы через сокеты (быстрее для одиночных хостов)
            # getaddrinfo вернет IP, если домен существует
            addr_info = await loop.run_in_executor(None, dns.resolver.resolve, subdomain_full, "A")
            ips = [str(rdata.address) for rdata in addr_info]
            if ips:
                return {"subdomain": subdomain_full, "ip": ips[0]}
        except Exception:
            return None
        return None


async def find_subdomains(domain: str, wordlist_path: str = "subdomains_wordlist.txt") -> list[dict]:
    """Асинхронный перебор поддоменов через asyncio.gather."""
    if not os.path.exists(wordlist_path):
        logging.error(f"[-] Файл словаря поддоменов не найден по пути: {wordlist_path}")
        return []

    with open(wordlist_path, "r", encoding="utf-8") as f:
        # Читаем строки, убираем пробелы и пустые элементы
        subdomains = [line.strip() for line in f if line.strip()]

    # Ограничиваем конкурентность, чтобы не забить DNS-сервер
    sem = asyncio.Semaphore(50)
    tasks = []

    for sub in subdomains:
        subdomain_full = f"{sub}.{domain}"
        tasks.append(_resolve_subdomain(subdomain_full, sem))

    logging.info(f"[*] Запущен асинхронный брут поддоменов для {domain} (задач: {len(tasks)})")

    # Собираем ответы
    results = await asyncio.gather(*tasks)

    # Фильтруем только успешные (не None)
    valid_subdomains = [res for res in results if res is not None]
    return valid_subdomains


# === Задача 17: Сборка OSINT в единый вывод (Контракт для Артёма) ===
async def run_osint(domain: str, wordlist_path: str = "subdomains_wordlist.txt") -> dict:
    """
    Последовательно запускает все три этапа OSINT разведки.
    Возвращает единый структурированный словарь-отчет.
    """
    logging.info(f"[*] Начало комплексного OSINT-анализа для домена: {domain}")

    whois_data = await get_whois(domain)
    dns_data = await get_dns(domain)
    subdomain_data = await find_subdomains(domain, wordlist_path)

    report = {
        "domain": domain,
        "scan_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "whois": whois_data,
        "dns": dns_data,
        "subdomains": subdomain_data
    }

    logging.info(f"[+] OSINT-анализ для {domain} успешно завершен.")
    return report