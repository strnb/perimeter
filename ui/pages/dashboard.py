import flet as ft
import sqlite3
import threading
from database import DB_PATH

def dashboard_page(page: ft.Page):
    
    # ============================================================
    # 1. СОЗДАЁМ ПУСТОЙ КАРКАС ИНТЕРФЕЙСА (без ожидания БД)
    # ============================================================
    
    # Заглушки, которые будут обновлены после загрузки данных
    index_value = ft.Text(
        "—", 
        size=54, 
        weight=ft.FontWeight.BOLD, 
        color="#a7a2be"
    )
    
    # Карточка индекса безопасности
    security_card = ft.Container(
        content=ft.Column(
            controls=[
                ft.Text("Индекс Безопасности", size=14, color="#a7a2be", weight=ft.FontWeight.W_500),
                index_value
            ],
            spacing=2
        ),
        bgcolor="#18122b",
        padding=20,
        border_radius=12,
        width=320,
        border=ft.Border(
            top=ft.BorderSide(1, "#393053"),
            bottom=ft.BorderSide(1, "#393053"),
            left=ft.BorderSide(1, "#393053"),
            right=ft.BorderSide(1, "#393053")
        )
    )

    # Фабрика бейджей с заглушками "—"
    def create_badge(label, neon_color):
        badge_value = ft.Text("—", size=26, weight=ft.FontWeight.BOLD, color="#ffffff")
        return ft.Container(
            content=ft.Column(
                controls=[
                    ft.Text(label, size=11, color="#a7a2be", weight=ft.FontWeight.W_500),
                    badge_value
                ],
                spacing=1
            ),
            bgcolor="#18122b",
            padding=15,
            border_radius=12,
            width=145,
            height=85,
            border=ft.Border(
                top=ft.BorderSide(1, neon_color),
                bottom=ft.BorderSide(1, neon_color),
                left=ft.BorderSide(1, neon_color),
                right=ft.BorderSide(1, neon_color)
            )
        ), badge_value  # Возвращаем кортеж (контейнер, ссылка на текст)

    # Создаём бейджи и сохраняем ссылки на текстовые поля
    crit_container, crit_text = create_badge("Критических", "#ff1744")
    med_container, med_text = create_badge("Средних", "#ff9100")
    low_container, low_text = create_badge("Низких", "#ffea00")

    counters_row = ft.Row(
        controls=[crit_container, med_container, low_container],
        spacing=15,
        alignment=ft.MainAxisAlignment.START
    )

    # ============================================================
    # 2. ФУНКЦИЯ БЕЗОПАСНОЙ ЗАГРУЗКИ ДАННЫХ ИЗ БД
    # ============================================================
    def load_data_from_db():
        """Загружает данные в отдельном потоке, не блокируя UI"""
        try:
            conn = sqlite3.connect(DB_PATH)
            cursor = conn.cursor()
            
            # Проверяем существование таблицы
            cursor.execute(
                "SELECT name FROM sqlite_master WHERE type='table' AND name='dlp_results'"
            )
            if not cursor.fetchone():
                conn.close()
                return 100, 0, 0, 0
            
            # Пытаемся получить последнюю запись
            cursor.execute(
                "SELECT critical_count, medium_count, low_count "
                "FROM dlp_results ORDER BY id DESC LIMIT 1"
            )
            row = cursor.fetchone()
            conn.close()
            
            if row and all(v is not None for v in row):
                c, m, l = row
            else:
                c, m, l = 0, 0, 0
            
            # Мягкая формула: не обнуляем индекс при первой же ошибке
            penalty = (c * 5) + (m * 3) + (l * 1)
            score = max(0, 100 - penalty)
            
            return score, c, m, l
            
        except Exception as ex:
            print(f"[DASHBOARD] Ошибка загрузки: {ex}")
            return 100, 0, 0, 0

    # ============================================================
    # 3. ОПРЕДЕЛЕНИЕ ЦВЕТА И СТАТУСА
    # ============================================================
    def get_index_color(val):
        if val >= 85:
            return "#00e676"   # Зелёный
        elif val >= 50:
            return "#ff9100"   # Оранжевый
        else:
            return "#ff1744"   # Красный

    # ============================================================
    # 4. КОЛБЭК ДЛЯ ОБНОВЛЕНИЯ UI (вызывается из главного потока)
    # ============================================================
    def update_ui(score, crit, med, low):
        """Обновляет текст и цвет элементов на странице"""
        index_value.value = str(score)
        index_value.color = get_index_color(score)
        
        crit_text.value = str(crit)
        med_text.value = str(med)
        low_text.value = str(low)
        
        # Безопасный вызов update() — только после полной сборки
        try:
            page.update()
        except Exception:
            pass

    # ============================================================
    # 5. ЗАПУСК АСИНХРОННОЙ ЗАГРУЗКИ ДАННЫХ
    # ============================================================
    def background_load():
        """Фоновая загрузка: читаем БД → обновляем UI в главном потоке"""
        score, crit, med, low = load_data_from_db()
        # Переносим обновление UI в главный поток Flet через page.run_task
        # Если run_task недоступен — используем threading.Timer как fallback
        try:
            page.run_thread(lambda: update_ui(score, crit, med, low))
        except AttributeError:
            # Fallback: простой таймер (менее элегантно, но работает)
            def delayed_update():
                update_ui(score, crit, med, low)
            threading.Timer(0.1, delayed_update).start()

    # Запускаем загрузку в отдельном потоке
    threading.Thread(target=background_load, daemon=True).start()

    # ============================================================
    # 6. ВОЗВРАЩАЕМ ГОТОВЫЙ КАРКАС СТРАНИЦЫ (мгновенно!)
    # ============================================================
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