import flet as ft
import api

def osint_page(page: ft.Page):
    header = ft.Text("Внешняя разведка (OSINT)", size=28, weight=ft.FontWeight.BOLD, color="#ffffff")

    domain_input = ft.TextField(
        label="Объект исследования (Домен)",
        label_style=ft.TextStyle(color="#a7a2be", size=13),
        border_color="#393053",
        focused_border_color="#b388ff",
        bgcolor="#130f22",
        expand=True,
        value="google.com"
    )

    console_output = ft.ListView(expand=True, spacing=5)

    async def start_osint_scan(e):
        console_output.controls.clear()
        console_output.controls.append(ft.Text(f"[*] Запуск OSINT-пайплайна для {domain_input.value}...", font_family="Courier New", color="#b388ff"))
        page.update()

        try:
            # Вызываем функцию из api.py
            result = await api.run_osint_report(domain_input.value, wordlist_path="core/subdomains_wordlist.txt")
            
            console_output.controls.append(ft.Text("[+] Разведка завершена:", font_family="Courier New", color="#00e676"))
            
            if not result:
                console_output.controls.append(ft.Text("[-] Модуль вернул пустой результат.", font_family="Courier New", color="#ff1744"))
            elif "error" in result:
                console_output.controls.append(ft.Text(f"[-] Ошибка пайплайна: {result['error']}", font_family="Courier New", color="#ff1744"))
            else:
                console_output.controls.append(ft.Text(f" -> Домен: {result.get('domain', domain_input.value)}", font_family="Courier New", color="#ffffff"))
                console_output.controls.append(ft.Text(f" -> Время сканирования: {result.get('scan_time', '-')}", font_family="Courier New", color="#ffffff"))
                
                # WHOIS
                whois_data = result.get('whois', {})
                if whois_data:
                    console_output.controls.append(ft.Text(" -> Данные WHOIS:", font_family="Courier New", color="#b388ff"))
                    for k, v in whois_data.items():
                        console_output.controls.append(ft.Text(f"    | {k}: {v}", font_family="Courier New", color="#a7a2be", selectable=True))
                
                # DNS
                dns_data = result.get('dns', {})
                if dns_data:
                    console_output.controls.append(ft.Text(" -> DNS записи:", font_family="Courier New", color="#b388ff"))
                    for record_type, ips in dns_data.items():
                        console_output.controls.append(ft.Text(f"    | {record_type}: {', '.join(ips) if isinstance(ips, list) else ips}", font_family="Courier New", color="#a7a2be", selectable=True))
                
                # Subdomains
                subdomains = result.get('subdomains', [])
                console_output.controls.append(ft.Text(f" -> Найдено поддоменов: {len(subdomains)}", font_family="Courier New", color="#b388ff"))
                for sub in subdomains:
                    if isinstance(sub, dict):
                        console_output.controls.append(ft.Text(f"    | {sub.get('subdomain')} -> IP: {sub.get('ip')}", font_family="Courier New", color="#ffeb3b", selectable=True))
                    else:
                        console_output.controls.append(ft.Text(f"    | {sub}", font_family="Courier New", color="#ffeb3b", selectable=True))

        except Exception as ex:
            console_output.controls.append(ft.Text(f"[-] Критический сбой интерфейса OSINT: {ex}", font_family="Courier New", color="#ff1744"))
        
        page.update()

    start_btn = ft.ElevatedButton(
        "Запустить анализ",
        icon=ft.Icons.SEARCH,
        bgcolor="#b388ff",
        color="#0b0813",
        on_click=start_osint_scan
    )

    search_row = ft.Row(controls=[domain_input, start_btn], spacing=12)

    results_box = ft.Container(
        content=ft.Column([
            ft.Text("Консоль вывода подсистемы разведки", size=14, color="#a7a2be"),
            ft.Divider(color="#251b45"),
            console_output
        ], spacing=8, expand=True),
        bgcolor="#18122b",
        padding=20,
        border_radius=12,
        # ИСПРАВЛЕНО: Безопасное объявление границ без использования .all()
        border=ft.Border(
            top=ft.BorderSide(1, "#393053"),
            bottom=ft.BorderSide(1, "#393053"),
            left=ft.BorderSide(1, "#393053"),
            right=ft.BorderSide(1, "#393053")
        ),
        expand=True
    )

    return ft.Column(controls=[header, search_row, ft.Divider(color="#251b45"), results_box], expand=True, spacing=20)