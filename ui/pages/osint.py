import flet as ft

def osint_page(page: ft.Page):
    header = ft.Text("Внешняя разведка (OSINT)", size=28, weight=ft.FontWeight.BOLD, color="#ffffff")

    search_input = ft.TextField(
        label="Объект исследования (Email, Домен, IP)",
        label_style=ft.TextStyle(color="#a7a2be", size=13),
        border_color="#393053",
        focused_border_color="#b388ff", 
        bgcolor="#130f22",
        cursor_color="#b388ff",
        expand=True
    )

    start_btn = ft.ElevatedButton(
        "Запустить анализ", 
        icon=ft.Icons.SEARCH,
        bgcolor="#b388ff",  
        color="#0b0813",
        style=ft.ButtonStyle(shape=ft.RoundedRectangleBorder(radius=8))
    )

    search_row = ft.Row(controls=[search_input, start_btn], spacing=12)

    results_box = ft.Container(
        content=ft.Column(
            controls=[
                ft.Text("Консоль вывода подсистемы разведки", size=14, color="#a7a2be"),
                ft.Divider(color="#251b45"),
                ft.Text("[*] Подключение к Shodan API и VirusTotal...", font_family="Courier New", color="#a7a2be"),
                ft.Text("[+] Утечек по базе компрометации сотрудников не найдено.", font_family="Courier New", color="#00e676"),
            ],
            spacing=8
        ),
        bgcolor="#18122b",
        padding=20,
        border_radius=12,
        border=ft.Border.all(1, "#393053"),
        expand=True
    )

    return ft.Column(controls=[header, search_row, ft.Divider(color="#251b45"), results_box], expand=True, spacing=20)