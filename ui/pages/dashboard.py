import flet as ft

def dashboard_page(page: ft.Page):
    security_card = ft.Container(
        content=ft.Column(
            controls=[
                ft.Text("Индекс Безопасности", size=14, color="#a7a2be", weight=ft.FontWeight.W_500),
                ft.Text("100", size=54, weight=ft.FontWeight.BOLD, color="#00e676") 
            ],
            spacing=2
        ),
        bgcolor="#18122b",
        padding=20,                           
        border_radius=12,                     
        width=320,
        border=ft.Border.all(1, "#393053") # ИСПРАВЛЕНО: ft.Border.all с большой буквы
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
            border=ft.Border.all(1, neon_color) # ИСПРАВЛЕНО: ft.Border.all с большой буквы
        )

    counters_row = ft.Row(
        controls=[
            create_badge("Критических", "3", "#ff1744"),   
            create_badge("Средних", "12", "#ff9100"),    
            create_badge("Низких", "5", "#ffea00"),     
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