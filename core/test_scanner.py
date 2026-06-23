import asyncio
from modules.scanner.port_scanner import scan_ports


async def main():
    # Полная подсеть локалхоста (254 хоста)
    target_cidr = "127.0.0.0/24"

    print(f"[*] Запуск нагрузочного теста на CIDR: {target_cidr}")

    # Сканируем стандартный список (11 портов). Итого 254 * 11 = 2794 проверки!
    # Ограничиваем concurrency в 100 потоков
    results = await scan_ports(target_cidr, max_concurrency=100)

    print("\n=== РЕЗУЛЬТАТЫ СКАНИРОВАНИЯ ===")
    if not results:
        print("[-] Открытых портов в подсети не обнаружено (или всё заблокировано).")
    for host, open_ports in results.items():
        print(f"[+] {host} -> Открыты: {open_ports}")


if __name__ == "__main__":
    asyncio.run(main())