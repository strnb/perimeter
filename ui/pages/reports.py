import flet as ft
from core.modules.report_generator_utils.report_generator import generate_pdf_report 
import database
import os

def reports_page(page: ft.Page):
    status_text = ft.Text("", color="#a7a2be", size=13)
    
    # Автоматически находим путь к Рабочему столу пользователя
    desktop_path = os.path.join(os.path.expanduser("~"), "Desktop")
    default_save_path = os.path.join(desktop_path, "Perimeter_Report.pdf")
    
    # Текстовое поле, в котором уже сразу прописан путь на Рабочий стол
    path_input = ft.TextField(
        label="Путь для сохранения PDF отчета",
        value=default_save_path,
        color="#ffffff",
        border_color="#393053",
        bgcolor="#130f22",
        width=500 # Сделали чуть шире, так как длинный путь к Рабочему столу должен помещаться
    )

    def on_generate_click(e):
        user_path = path_input.value.strip()
        if not user_path:
            status_text.value = "Ошибка: Укажите путь для сохранения файла!"
            status_text.color = "#ff1744"
            page.update()
            return

        status_text.value = f"Генерация PDF по указанному пути..."
        status_text.color = "#a7a2be"
        page.update()
        
        try:
            # Запускаем генератор отчетов
            generate_pdf_report(user_path)
            
            status_text.value = f"Успешно! Отчет сохранен:\n{user_path}"
            status_text.color = "#00e676"
        except Exception as ex:
            status_text.value = f"Ошибка записи PDF: {str(ex)}"
            status_text.color = "#ff1744"
        page.update()

    def on_clear_click(e):
        try:
            database.clear_all_data()
            status_text.value = "База данных успешно очищена! Все логи удалены."
            status_text.color = "#ffea00"
        except Exception as ex:
            status_text.value = f"Ошибка очистки БД: {str(ex)}"
            status_text.color = "#ff1744"
        page.update()

    btn_generate = ft.ElevatedButton(
        content=ft.Row(
            [
                ft.Icon(ft.Icons.PICTURE_AS_PDF, color="#ffffff"),
                ft.Text("Сформировать и экспортировать отчет", color="#ffffff"),
            ],
            spacing=10,
            alignment=ft.MainAxisAlignment.CENTER
        ),
        style=ft.ButtonStyle(bgcolor="#251b45"),
        width=340,
        on_click=on_generate_click
    )

    btn_clear = ft.ElevatedButton(
        content=ft.Row(
            [
                ft.Icon(ft.Icons.DELETE_FOREVER, color="#ffffff"),
                ft.Text("Очистить историю логов", color="#ffffff"),
            ],
            spacing=10,
            alignment=ft.MainAxisAlignment.CENTER
        ),
        style=ft.ButtonStyle(bgcolor="#b71c1c"),
        width=240,
        on_click=on_clear_click
    )

    return ft.Column(
        controls=[
            ft.Text("Генерация отчетов", size=28, weight=ft.FontWeight.BOLD, color="#ffffff"),
            ft.Divider(color="#251b45"),
            ft.Text("Подсистема агрегации данных формирует PDF-документы на основе логов аудита безопасности, извлеченных из единой базы данных SQLite.", color="#a7a2be", size=14),
            
            ft.Container(height=10),
            
            ft.Container(
                content=ft.Column([
                    ft.Text("Экспорт данных", size=16, weight=ft.FontWeight.BOLD),
                    ft.Text("По умолчанию выбран ваш Рабочий стол. При необходимости измените путь вручную.", size=12, color="#a7a2be"),
                    
                    ft.Container(height=15),
                    path_input,
                    ft.Container(height=10),
                    
                    ft.Row(
                        controls=[btn_generate, btn_clear],
                        spacing=15,
                        alignment=ft.MainAxisAlignment.START
                    ),
                    
                    ft.Container(height=15),
                    status_text
                ]),
                bgcolor="#18122b",
                padding=20,
                border_radius=12,
                border=ft.Border(
                    top=ft.BorderSide(1, "#393053"),
                    bottom=ft.BorderSide(1, "#393053"),
                    left=ft.BorderSide(1, "#393053"),
                    right=ft.BorderSide(1, "#393053")
                )
            )
        ],
        spacing=20
    )