import asyncio
from modules.scanner.banner import grab_http, grab_ssh


async def main():
    print("[*] Тестирование сбора баннеров...")

    # 1. Тест HTTP баннера на google.com (порт 80)
    http_banner = await grab_http("google.com", 80)
    print(f"[+] Google HTTP Banner: {http_banner}")

    # 2. Тест HTTPS баннера на github.com (порт 443)
    https_banner = await grab_http("github.com", 443)
    print(f"[+] GitHub HTTPS Banner: {https_banner}")

    # 3. Тест SSH баннера на scanme.nmap.org (порт 22)
    ssh_banner = await grab_ssh("scanme.nmap.org", 22)
    print(f"[+] Nmap SSH Banner: {ssh_banner}")


if __name__ == "__main__":
    asyncio.run(main())