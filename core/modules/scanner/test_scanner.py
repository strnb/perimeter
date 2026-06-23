# test_scanner.py
import asyncio
from modules.scanner.port_scanner import scan_port

async def main():
    host = "127.0.0.1"
    
    print(f"[*] Проверка {host}...")
    
    # Тест порта 22
    res_22 = await scan_port(host, 22)
    print(f"[-] Порт 22: {'ОТКРЫТ' if res_22 else 'ЗАКРЫТ'}")
    
    # Тест порта 9999
    res_9999 = await scan_port(host, 9999)
    print(f"[-] Порт 9999: {'ОТКРЫТ' if res_9999 else 'ЗАКРЫТ'}")

if __name__ == "__main__":
    asyncio.run(main())