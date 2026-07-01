import flet as ft
import api  
import sqlite3
from database import DB_PATH

def dashboard_page(page: ft.Page):
    # Получаем данные последнего DLP-сканирования из БД
    critical_count = 0
    medium_count = 0
    low_count = 0
    current_index = 100

    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute("SELECT critical_count, medium_count, low_count FROM dlp_results ORDER BY id DESC LIMIT 1")
        row = cursor.fetchone()
        conn.close()
        
        if row:
            critical_count, medium_count, low_count = row
            # Рассчитываем индекс безопасности на основе находок
            score = 100 - (critical_count * 10) - (medium_count * 5) - (low_count * 2)
            current_index = max(0, score)
    except Exception as ex:
        print(f"[DASHBOARD] Ошибка получения данных из БД: {ex}")
    
    security_card = ft.Container(        content=ft.Column(
            controls=[
                ft.Text("Индекс Безопасности", size=14, color="#a7a2be", weight=ft.FontWeight.W_500),
                ft.Text(str(current_index), size=54, weight=ft.FontWeight.BOLD, color="#00e676" if current_index > 70 else "#ff9100") 
            ],
            spacing=2
        ),
        bgcolor="#18122b",
        padding=20,                                           
        border_radius=12,                                     
        width=320,
        # ИСПРАВЛЕНО: Безопасные границы без .all()
        border=ft.Border(
            top=ft.BorderSide(1, "#393053"),
            bottom=ft.BorderSide(1, "#393053"),
            left=ft.BorderSide(1, "#393053"),
            right=ft.BorderSide(1, "#393053")
        )
    )

    def create_badge(label, value, neon_color):
        return ft.Container(
            content=ft.Column(
                controls=[
                    ft.Text(label, size=11, color="#a7a2be", weight=ft.FontWeight.W_500),
                    ft.Text(value, size=26, weight=ft.FontWeight.BOLD, color="#ffffff")      
                ],
                spacing=1
            ),
            bgcolor="#18122b", 
            padding=15,                                           
            border_radius=12,                                      
            width=145,                                             
            height=85,                                             
            # ИСПРАВЛЕНО: Безопасные границы без .all()
            border=ft.Border(
                top=ft.BorderSide(1, neon_color),
                bottom=ft.BorderSide(1, neon_color),
                left=ft.BorderSide(1, neon_color),
                right=ft.BorderSide(1, neon_color)
            )
        )

    # Выводим реальные счетчики (пока завязаны на логику индекса: если индекс < 100, значит что-то нашли)
    # Для полноценного отображения можно будет связать с массивом raw_findings из dlp.py
    counters_row = ft.Row(
        controls=[
            create_badge("Критических", str(critical_count), "#ff1744"),   
            create_badge("Средних", str(medium_count), "#ff9100"),    
            create_badge("Низких", str(low_count), "#ffea00"),     
        ],
        spacing=15, 
        alignment=ft.MainAxisAlignment.START 
    )

    return ft.Column(
        controls=[
            ft.Text("Главная", size=28, weight=ft.FontWeight.BOLD, color="#ffffff"), 
            ft.Divider(color="#251b45"), 
            security_card, 
            ft.Text("Сводка текущих угроз:", size=14, color="#a7a2be", weight=ft.FontWeight.W_500),
            counters_row,  
        ],
        alignment=ft.MainAxisAlignment.START,
        spacing=20 
    )