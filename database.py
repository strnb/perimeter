import sqlite3
import os
import logging
import json
import json
from datetime import datetime

logger = logging.getLogger(__name__)

CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))

BASE_DIR = (
    os.path.abspath(os.path.join(CURRENT_DIR, os.pardir))
    if "ui" in CURRENT_DIR or "utils" in CURRENT_DIR or "core" in CURRENT_DIR
    else CURRENT_DIR
)

DB_PATH = os.path.join(BASE_DIR, "perimeter.db")

logger.debug(f"[DATABASE] DB path: {DB_PATH}")


# ============================================================
# ИНИЦИАЛИЗАЦИЯ
# ============================================================

def init_db():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS osint_results(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        scan_time TEXT,
        target_domain TEXT,
        registrar TEXT,
        subdomains_count INTEGER
    )
    """)

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS dlp_results(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        scan_time TEXT,
        checked_path TEXT,
        critical_count INTEGER,
        medium_count INTEGER,
        low_count INTEGER
    )
    """)

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS network_results(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        scan_time TEXT,
        target TEXT,
        open_ports_count INTEGER,
        vulnerabilities_count INTEGER
    )
    """)

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS network_details(
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

    # --------------------------------------------------------
    # История запусков
    # --------------------------------------------------------

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS scan_summaries(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        scan_time TEXT NOT NULL,
        target TEXT NOT NULL,
        mode TEXT NOT NULL,
        score INTEGER
    )
    """)

    # --------------------------------------------------------
    # Полный JSON результата проверки
    # --------------------------------------------------------

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS scan_results(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        summary_id INTEGER UNIQUE,
        result_json TEXT NOT NULL,
        FOREIGN KEY(summary_id)
            REFERENCES scan_summaries(id)
            ON DELETE CASCADE
    )
    """)

    conn.commit()
    conn.close()


# ============================================================
# СТАРЫЕ ФУНКЦИИ
# ============================================================

def save_osint_result(scan_time, target_domain, registrar, subdomains_count):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    cursor.execute("""
    INSERT INTO osint_results
    (scan_time,target_domain,registrar,subdomains_count)
    VALUES(?,?,?,?)
    """, (
        scan_time,
        target_domain,
        registrar,
        subdomains_count,
    ))

    conn.commit()
    conn.close()


def save_dlp_result(scan_time, checked_path,
                    critical_count,
                    medium_count,
                    low_count):

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    cursor.execute("""
    INSERT INTO dlp_results
    VALUES(NULL,?,?,?,?,?)
    """, (
        scan_time,
        checked_path,
        critical_count,
        medium_count,
        low_count,
    ))

    conn.commit()
    conn.close()


def save_network_result(
        scan_time,
        target,
        open_ports_count,
        vulnerabilities_count,
        details):

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    cursor.execute("""
    INSERT INTO network_results
    VALUES(NULL,?,?,?,?)
    """, (
        scan_time,
        target,
        open_ports_count,
        vulnerabilities_count,
    ))

    result_id = cursor.lastrowid

    for detail in details:

        cursor.execute("""
        INSERT INTO network_details
        VALUES(NULL,?,?,?,?,?,?)
        """, (
            result_id,
            detail["port"],
            detail["service"],
            detail["banner"],
            detail.get("vulnerability_title"),
            detail.get("severity"),
        ))

    conn.commit()
    conn.close()


# ============================================================
# НОВАЯ ИСТОРИЯ
# ============================================================

def save_scan_summary(
        scan_time: str,
        target: str,
        mode: str,
        score: int):

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    cursor.execute(
        """
        INSERT INTO scan_summaries
        (scan_time,target,mode,score)
        VALUES(?,?,?,?)
        """,
        (
            scan_time,
            target,
            mode,
            score,
        )
    )

    summary_id = cursor.lastrowid

    conn.commit()
    conn.close()

    return summary_id


def _json_serializer(obj):
    """
    Автоматически сериализует объекты,
    которые json.dumps не умеет сохранять.
    """
    if isinstance(obj, datetime):
        return obj.isoformat()
    if isinstance(obj, set):
        return list(obj)
    if isinstance(obj, Path):
        return str(obj)
    return str(obj)

def save_scan_result(summary_id: int,
                     result: dict):

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    cursor.execute(
        """
        INSERT OR REPLACE INTO scan_results
        (summary_id,result_json)
        VALUES(?,?)
        """,
        (
            summary_id,
            json.dumps(
                result,
                ensure_ascii=False
            )
        )
    )

    conn.commit()
    conn.close()


def get_scan_result(summary_id: int):

    conn = sqlite3.connect(DB_PATH)

    cursor = conn.cursor()

    cursor.execute(
        """
        SELECT result_json
        FROM scan_results
        WHERE summary_id=?
        """,
        (
            summary_id,
        )
    )

    row = cursor.fetchone()

    conn.close()

    if row is None:
        return None

    return json.loads(row[0])


def get_recent_scans(limit=5):

    conn = sqlite3.connect(DB_PATH)

    cursor = conn.cursor()

    cursor.execute("""
    SELECT
        id,
        scan_time,
        target,
        mode,
        score
    FROM scan_summaries
    ORDER BY id DESC
    LIMIT ?
    """, (
        limit,
    ))

    rows = cursor.fetchall()

    conn.close()

    return rows


# ============================================================
# УДАЛЕНИЕ
# ============================================================

def delete_scan(summary_id: int):

    conn = sqlite3.connect(DB_PATH)

    cursor = conn.cursor()

    cursor.execute(
        "DELETE FROM scan_results WHERE summary_id=?",
        (
            summary_id,
        )
    )

    cursor.execute(
        "DELETE FROM scan_summaries WHERE id=?",
        (
            summary_id,
        )
    )

    conn.commit()
    conn.close()


def clear_all_data():

    conn = sqlite3.connect(DB_PATH)

    cursor = conn.cursor()

    cursor.execute("DELETE FROM scan_results")
    cursor.execute("DELETE FROM scan_summaries")

    cursor.execute("DELETE FROM osint_results")
    cursor.execute("DELETE FROM dlp_results")
    cursor.execute("DELETE FROM network_results")
    cursor.execute("DELETE FROM network_details")

    conn.commit()
    conn.close()


init_db()