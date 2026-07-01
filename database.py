import sqlite3
import os
from datetime import datetime

CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))

BASE_DIR = os.path.abspath(os.path.join(CURRENT_DIR, os.pardir)) if "ui" in CURRENT_DIR or "utils" in CURRENT_DIR or "core" in CURRENT_DIR else CURRENT_DIR

DB_PATH = os.path.join(BASE_DIR, "perimeter.db")
print(f"[DATABASE] Используется единый путь к БД: {DB_PATH}") # Для отладки в консоли

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
    
    conn.commit()
    conn.close()

def clear_all_data():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("DROP TABLE IF EXISTS osint_results")
    cursor.execute("DROP TABLE IF EXISTS dlp_results")
    conn.commit()
    conn.close()
    init_db()  # Пересоздаем пустые таблицы

# Вызываем инициализацию при импорте модуля
init_db()