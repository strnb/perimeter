import sqlite3
import os

from core.paths import app_data_dir

CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))

# В репозитории/editable-установке история лежит рядом с кодом, как раньше.
# После обычного pip install site-packages только для чтения — уходим в ~/.perimeter.
if os.path.isdir(os.path.join(CURRENT_DIR, "knowledge_base")):
    DB_PATH = os.path.join(CURRENT_DIR, "perimeter.db")
else:
    DB_PATH = str(app_data_dir() / "perimeter.db")

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
        subdomains_count INTEGER,
        expires_at TEXT,
        findings_count INTEGER DEFAULT 0
    )
    """)

    # Миграция старых БД: срок домена и число находок
    osint_columns = {row[1] for row in cursor.execute("PRAGMA table_info(osint_results)")}
    if "expires_at" not in osint_columns:
        cursor.execute("ALTER TABLE osint_results ADD COLUMN expires_at TEXT")
    if "findings_count" not in osint_columns:
        cursor.execute("ALTER TABLE osint_results ADD COLUMN findings_count INTEGER DEFAULT 0")

    # Поддомены отдельно — по ним считается diff с прошлым сканом
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS osint_subdomains (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        result_id INTEGER,
        name TEXT,
        ips TEXT,
        cname TEXT,
        source TEXT,
        http_status INTEGER,
        title TEXT,
        FOREIGN KEY(result_id) REFERENCES osint_results(id) ON DELETE CASCADE
    )
    """)
    
    # Создаем таблицу DLP, если её нет
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS dlp_results (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        scan_time TEXT,
        checked_path TEXT,
        critical_count INTEGER,
        high_count INTEGER DEFAULT 0,
        medium_count INTEGER,
        low_count INTEGER
    )
    """)

    # Миграция старых БД: HIGH больше не считается CRITICAL
    dlp_columns = {row[1] for row in cursor.execute("PRAGMA table_info(dlp_results)")}
    if "high_count" not in dlp_columns:
        cursor.execute("ALTER TABLE dlp_results ADD COLUMN high_count INTEGER DEFAULT 0")

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
        host TEXT,
        port INTEGER,
        service TEXT,
        banner TEXT,
        vulnerability_title TEXT,
        severity TEXT,
        FOREIGN KEY(result_id) REFERENCES network_results(id) ON DELETE CASCADE
    )
    """)

    # Миграция старых БД: без host в отчёте по подсети не видно, где найден порт
    columns = {row[1] for row in cursor.execute("PRAGMA table_info(network_details)")}
    if "host" not in columns:
        cursor.execute("ALTER TABLE network_details ADD COLUMN host TEXT")
    
    conn.commit()
    conn.close()

def save_osint_result(scan_time, target_domain, registrar, subdomains_count,
                      expires_at=None, findings_count=0, subdomains=None):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("""
    INSERT INTO osint_results
        (scan_time, target_domain, registrar, subdomains_count, expires_at, findings_count)
    VALUES (?, ?, ?, ?, ?, ?)
    """, (scan_time, target_domain, registrar, subdomains_count, expires_at, findings_count))
    result_id = cursor.lastrowid

    for sub in subdomains or []:
        info = sub.get("http") or {}
        cursor.execute("""
        INSERT INTO osint_subdomains
            (result_id, name, ips, cname, source, http_status, title)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (
            result_id,
            sub.get("subdomain"),
            ",".join(sub.get("ips") or []),
            sub.get("cname"),
            sub.get("source"),
            info.get("status"),
            info.get("title"),
        ))

    conn.commit()
    conn.close()


def get_previous_osint_subdomains(target_domain):
    """Имена поддоменов из последнего сохранённого скана домена."""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    row = cursor.execute(
        "SELECT id FROM osint_results WHERE target_domain = ? ORDER BY id DESC LIMIT 1",
        (target_domain,),
    ).fetchone()
    names = set()
    if row:
        names = {
            name for (name,) in cursor.execute(
                "SELECT name FROM osint_subdomains WHERE result_id = ?", (row[0],)
            )
        }
    conn.close()
    return names

def save_dlp_result(scan_time, checked_path, critical_count, medium_count, low_count,
                    high_count=0):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("""
    INSERT INTO dlp_results
        (scan_time, checked_path, critical_count, high_count, medium_count, low_count)
    VALUES (?, ?, ?, ?, ?, ?)
    """, (scan_time, checked_path, critical_count, high_count, medium_count, low_count))
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
        INSERT INTO network_details (result_id, host, port, service, banner, vulnerability_title, severity)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (result_id, detail.get('host'), detail['port'], detail['service'], detail['banner'],
              detail.get('vulnerability_title'), detail.get('severity')))
        
    conn.commit()
    conn.close()

def clear_all_data():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("DROP TABLE IF EXISTS osint_subdomains")
    cursor.execute("DROP TABLE IF EXISTS osint_results")
    cursor.execute("DROP TABLE IF EXISTS dlp_results")
    cursor.execute("DROP TABLE IF EXISTS network_results")
    cursor.execute("DROP TABLE IF EXISTS network_details")
    conn.commit()
    conn.close()
    init_db()  # Пересоздаем пустые таблицы
