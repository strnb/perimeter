import flet as ft
import api

def osint_page(page: ft.Page):
    header = ft.Text("Внешняя разведка (OSINT)", size=28, weight=ft.FontWeight.BOLD, color="#ffffff")

    search_input = ft.TextField(
        label="Объект исследования (Домен)",
        label_style=ft.TextStyle(color="#a7a2be", size=13),
        border_color="#393053",
        focused_border_color="#b388ff",
        bgcolor="#130f22",
        expand=True
    )

    console_output = ft.Column(spacing=5)

    async def start_osint_click(e):
        if not search_input.value:
            return
        
        console_output.controls.clear()
        console_output.controls.append(ft.Text(f"[*] Запуск OSINT-пайплайна для {search_input.value}...", font_family="Courier New", color="#b388ff"))
        page.update() # ИСПРАВЛЕНО

        try:
            report = await api.run_osint_report(search_input.value)
            
            if "error" in report:
                console_output.controls.append(ft.Text(f"[-] Ошибка подсистемы: {report['error']}", font_family="Courier New", color="#ff1744"))
            else:
                console_output.controls.append(ft.Text("[+] Разведка завершена:", font_family="Courier New", color="#00e676"))
                for key, val in report.items():
                    console_output.controls.append(ft.Text(f" -> {key}: {str(val)[:100]}...", font_family="Courier New", color="#ffffff"))
        except Exception as ex:
            console_output.controls.append(ft.Text(f"[-] Ошибка выполнения: {ex}", font_family="Courier New", color="#ff1744"))
        
        page.update() # ИСПРАВЛЕНО

    start_btn = ft.ElevatedButton(
        "Запустить анализ",
        icon=ft.Icons.SEARCH,
        bgcolor="#b388ff",
        color="#0b0813",
        on_click=start_osint_click
    )

    search_row = ft.Row(controls=[search_input, start_btn], spacing=12)

    results_box = ft.Container(
        content=ft.Column([
            ft.Text("Консоль вывода подсистемы разведки", size=14, color="#a7a2be"),
            ft.Divider(color="#251b45"),
            ft.ListView(controls=[console_output], expand=True)
        ], spacing=8),
        bgcolor="#18122b",
        padding=20,
        border_radius=12,
        border=ft.Border.all(1, "#393053"),
        expand=True
    )

    return ft.Column(controls=[header, search_row, ft.Divider(color="#251b45"), results_box], expand=True, spacing=20)