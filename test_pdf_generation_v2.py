import os
import sqlite3
from datetime import datetime
import database
from core.modules.report_generator_utils.report_generator import generate_pdf_report

def test_pipeline():
    print("[*] Инициализация БД...")
    database.init_db()
    
    print("[*] Очистка старых данных...")
    database.clear_all_data()
    
    print("[*] Добавление тестовых данных OSINT...")
    database.save_osint_result(
        scan_time=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        target_domain="example.com",
        registrar="REGRU-RU",
        subdomains_count=3
    )
    
    print("[*] Добавление тестовых данных DLP...")
    database.save_dlp_result(
        scan_time=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        checked_path="/home/user/project",
        critical_count=2,
        medium_count=5,
        low_count=10
    )
    
    print("[*] Добавление тестовых данных Network...")
    details = [
        {
            "port": 80,
            "service": "http",
            "banner": "nginx/1.18.0",
            "vulnerability_title": "Outdated nginx version",
            "severity": "MEDIUM"
        },
        {
            "port": 22,
            "service": "ssh",
            "banner": "OpenSSH 8.2p1",
            "vulnerability_title": "SSH Weak Algorithms",
            "severity": "LOW"
        },
        {
            "port": 443,
            "service": "https",
            "banner": "nginx/1.18.0",
            "vulnerability_title": None,
            "severity": None
        }
    ]
    database.save_network_result(
        scan_time=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        target="192.168.1.1",
        open_ports_count=3,
        vulnerabilities_count=2,
        details=details
    )
    
    print("[*] Генерация расширенного PDF-отчета...")
    report_path = "test_report_v2.pdf"
    if os.path.exists(report_path):
        os.remove(report_path)
        
    generate_pdf_report(report_path)
    
    if os.path.exists(report_path) and os.path.getsize(report_path) > 0:
        print(f"[+] Успех! Расширенный PDF-отчет успешно сгенерирован: {report_path} ({os.path.getsize(report_path)} байт)")
    else:
        print("[-] Ошибка: PDF-отчет не был создан или пуст.")

if __name__ == "__main__":
    test_pipeline()
