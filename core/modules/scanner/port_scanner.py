import asyncio
import logging
import ipaddress
import time

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

DEFAULT_PORTS = [21, 22, 23, 80, 443, 3306, 5432, 6379, 27017, 8080, 8443]


# Добавляем семафор в аргументы. Мы оборачиваем логику scan_port.
async def scan_port(host: str, port: int, semaphore: asyncio.Semaphore, timeout: float = 1.0) -> tuple[str, int, bool]:
    """
    Сканирует один порт с использованием семафора для ограничения конкурентности.
    Возвращает кортеж (host, port, is_open).
    """
    # async with гарантирует: зашли в блок — заняли 1 слот из 100, вышли (даже с ошибкой) — освободили slot
    async with semaphore:
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port),
                timeout=timeout
            )
            writer.close()
            await writer.wait_closed()
            return host, port, True
        except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
            return host, port, False


async def scan_ports(target: str, ports: list[int] = None, max_concurrency: int = 100) -> dict[str, list[int]]:
    """
    Сканирует цель (IP или CIDR) с ограничением конкурентных соединений (Semaphore).
    """
    if ports is None:
        ports = DEFAULT_PORTS

    if "/" in target:
        hosts_to_scan = expand_cidr(target)
    else:
        hosts_to_scan = [target]

    # Инициализируем семафор с лимитом (например, 100)
    sem = asyncio.Semaphore(max_concurrency)

    # Фиксируем время начала для замера скорости (требование Задачи 5)
    start_time = time.time()

    logging.info(f"[*] Глобальный старт. Хостов: {len(hosts_to_scan)}, портов на хост: {len(ports)}.")
    logging.info(f"[*] Лимит одновременных соединений (Semaphore): {max_concurrency}")

    # Генерируем плоский список ВСЕХ задач для ВСЕХ хостов
    tasks = []
    for host in hosts_to_scan:
        for port in ports:
            tasks.append(scan_port(host, port, semaphore=sem))

    # Запускаем всё "одновременно". Семафор сам будет придерживать лишние задачи в очереди.
    results = await asyncio.gather(*tasks)

    # Собираем красивый финальный словарь результатов
    results_dict = {}
    for host, port, is_open in results:
        if is_open:
            if host not in results_dict:
                results_dict[host] = []
            results_dict[host].append(port)

    end_time = time.time()
    logging.info(f"[+] Сканирование завершено за {end_time - start_time:.2f} секунд.")

    return results_dict


def expand_cidr(cidr: str) -> list[str]:
    try:
        network = ipaddress.ip_network(cidr, strict=False)
        if network.num_addresses > 256:
            logging.warning(f"[!] Внимание: подсеть {cidr} содержит {network.num_addresses} хостов!")
        return [str(ip) for ip in network.hosts()]
    except ValueError as e:
        logging.error(f"[-] Ошибка парсинга CIDR: {e}")
        return []