import sqlite3
import os
from datetime import datetime

CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))

DB_PATH = os.path.join(CURRENT_DIR, "perimeter.db")

def init_db():
    """Гарантирует создание всех необходимых таблиц при старте приложения."""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    # Создаем таблицу OSINT, если её нет
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS osint_results (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        scan_time TEXT,
        target_domain TEXT,
        registrar TEXT,
        subdomains_count INTEGER
    )
    """)
    
    # Создаем таблицу DLP, если её нет
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS dlp_results (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        scan_time TEXT,
        checked_path TEXT,
        critical_count INTEGER,
        medium_count INTEGER,
        low_count INTEGER
    )
    """)

    # Создаем таблицу Network результатов, если её нет
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS network_results (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        scan_time TEXT,
        target TEXT,
        open_ports_count INTEGER,
        vulnerabilities_count INTEGER
    )
    """)
    
    # Создаем таблицу деталей Network, если её нет
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS network_details (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        result_id INTEGER,
        port INTEGER,
        service TEXT,
        banner TEXT,
        vulnerability_title TEXT,
        severity TEXT,
        FOREIGN KEY(result_id) REFERENCES network_results(id) ON DELETE CASCADE
    )
    """)
    
    conn.commit()
    conn.close()

def save_osint_result(scan_time, target_domain, registrar, subdomains_count):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("""
    INSERT INTO osint_results (scan_time, target_domain, registrar, subdomains_count)
    VALUES (?, ?, ?, ?)
    """, (scan_time, target_domain, registrar, subdomains_count))
    conn.commit()
    conn.close()

def save_dlp_result(scan_time, checked_path, critical_count, medium_count, low_count):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("""
    INSERT INTO dlp_results (scan_time, checked_path, critical_count, medium_count, low_count)
    VALUES (?, ?, ?, ?, ?)
    """, (scan_time, checked_path, critical_count, medium_count, low_count))
    conn.commit()
    conn.close()

def save_network_result(scan_time, target, open_ports_count, vulnerabilities_count, details):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("""
    INSERT INTO network_results (scan_time, target, open_ports_count, vulnerabilities_count)
    VALUES (?, ?, ?, ?)
    """, (scan_time, target, open_ports_count, vulnerabilities_count))
    result_id = cursor.lastrowid
    
    for detail in details:
        cursor.execute("""
        INSERT INTO network_details (result_id, port, service, banner, vulnerability_title, severity)
        VALUES (?, ?, ?, ?, ?, ?)
        """, (result_id, detail['port'], detail['service'], detail['banner'], detail.get('vulnerability_title'), detail.get('severity')))
        
    conn.commit()
    conn.close()

def clear_all_data():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("DROP TABLE IF EXISTS osint_results")
    cursor.execute("DROP TABLE IF EXISTS dlp_results")
    cursor.execute("DROP TABLE IF EXISTS network_results")
    cursor.execute("DROP TABLE IF EXISTS network_details")
    conn.commit()
    conn.close()
    init_db()  # Пересоздаем пустые таблицы
# Вызываем инициализацию при импорте модуля
init_db()