import asyncio
from modules.scanner.db_checker import check_redis, check_mongo


async def main():
    # Будем тестировать на локалхосте (предполагаем, что контейнеры запущены)
    target_host = "127.0.0.1"

    print("[*] Запуск тестов для СУБД Детекторов...")

    # 1. Тестируем Redis
    print("[*] Проверка Redis (6379)...")
    redis_res = await check_redis(target_host, 6379)
    print(f"[+] Результат Redis: {redis_res}")

    # 2. Тестируем MongoDB
    print("[*] Проверка MongoDB (27017)...")
    mongo_res = await check_mongo(target_host, 27017)
    print(f"[+] Результат MongoDB: {mongo_res}")


if __name__ == "__main__":
    asyncio.run(main())