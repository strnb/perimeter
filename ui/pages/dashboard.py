import flet as ft
import api  # Импортируем готовый API Дамира

def dashboard_page(page: ft.Page):
    # Получаем реальный индекс безопасности (по умолчанию 100)
    current_index = api.get_security_index()

    security_card = ft.Container(
        content=ft.Column(
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
        border=ft.Border.all(1, "#393053")
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
            border=ft.Border.all(1, neon_color)
        )

    # Пока реального скана DLP не было, тут стоят базовые цифры
    counters_row = ft.Row(
        controls=[
            create_badge("Критических", "0", "#ff1744"),   
            create_badge("Средних", "0", "#ff9100"),    
            create_badge("Низких", "0", "#ffea00"),     
        ],
        spacing=15, 
        alignment=ft.MainAxisAlignment.START 
    )

    return ft.Column(
        controls=[
            ft.Text("Dashboard", size=28, weight=ft.FontWeight.BOLD, color="#ffffff"), 
            ft.Divider(color="#251b45"), 
            security_card, 
            ft.Text("Сводка текущих угроз:", size=14, color="#a7a2be", weight=ft.FontWeight.W_500),
            counters_row,  
        ],
        alignment=ft.MainAxisAlignment.START,
        spacing=20 
    )