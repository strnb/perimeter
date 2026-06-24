import asyncio
import json
from modules.scanner.osint import run_osint


async def main():
    target_domain = "google.com"

    print(f"[*] Тестируем сборку OSINT для {target_domain}...")

    # Запускаем полный цикл OSINT-разведки
    osint_report = await run_osint(target_domain, wordlist_path="subdomains_wordlist.txt")

    # Выводим в красивом JSON-формате, чтобы оценить структуру (контракт) для Артёма
    print("\n" + "=" * 20 + " OSINT REPORT JSON FOR ARTEM " + "=" * 20)
    print(json.dumps(osint_report, indent=4, ensure_ascii=False))
    print("=" * 69)


if __name__ == "__main__":
    asyncio.run(main())