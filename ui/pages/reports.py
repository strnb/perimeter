import flet as ft

def reports_page(page: ft.Page):
    header = ft.Text("Генерация отчетов", size=28, weight=ft.FontWeight.BOLD, color="#ffffff")

    report_box = ft.Container(
        content=ft.Column(
            controls=[
                ft.Text("Экспорт накопленной ИБ-статистики", size=16, weight=ft.FontWeight.W_500, color="#ffffff"),
                ft.Divider(color="#251b45"),
                ft.Row(
                    controls=[
                        ft.ElevatedButton("Экспорт PDF", icon=ft.Icons.PICTURE_AS_PDF, bgcolor="#130f22", color="#ffffff"),
                        ft.ElevatedButton("Экспорт Excel", icon=ft.Icons.TABLE_CHART, bgcolor="#130f22", color="#ffffff"),
                    ],
                    spacing=15
                )
            ],
            spacing=12
        ),
        bgcolor="#18122b",
        padding=20,
        border_radius=12,
        border=ft.Border.all(1, "#393053")
    )

    return ft.Column(controls=[header, ft.Divider(color="#251b45"), report_box], expand=True, spacing=20)