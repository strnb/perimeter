import asyncio
from modules.scanner.port_scanner import scan_ports


async def main():
    target = "127.0.0.1"
    print(f"[*] Запуск финального сканирования на {target}...")

    # Проверяем SSH, HTTP, HTTPS и Redis локально
    detected = await scan_ports(target, ports=[22, 80, 443, 6379, 27017])

    print("\n" + "=" * 35 + " FINAL PERIMETER REPORT " + "=" * 35)
    if not detected:
        print("[-] На хосте нет открытых портов из проверяемых.")
    for res in detected:
        print(f"[+] PORT: {res.port:<5} | SERVICE: {res.service:<8} | INFO/BANNER: {res.banner}")
    print("=" * 94)


if __name__ == "__main__":
    asyncio.run(main())