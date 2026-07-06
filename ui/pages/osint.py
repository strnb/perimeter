import flet as ft
import api
import database

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
    
    # ДОБАВЛЕНО: Индикатор прогресса, изначально скрыт
    progress_indicator = ft.ProgressRing(visible=False, width=20, height=20, stroke_width=3, value=None)

    async def start_osint_scan(e):
        domain = domain_input.value.strip() if domain_input.value else ""
        
        # ВАЛИДАЦИЯ ВВОДА: Проверка на пустоту или отсутствие точки в домене
        if not domain or "." not in domain:
            snack = ft.SnackBar(
                content=ft.Text("Введите корректный домен (например, google.com)"),
                bgcolor="#b71c1c"
            )
            page.overlay.append(snack)
            snack.open = True
            page.update()
            return  # Гарантированный останов выполнения
            
        # ИЗМЕНЕНО: Блокируем элементы управления и показываем лоадер
        start_btn.disabled = True
        progress_indicator.visible = True
        console_output.controls.clear()
        console_output.controls.append(ft.Text(f"[*] Запуск OSINT-пайплайна для {domain}...", font_family="Courier New", color="#b388ff"))
        page.update()

        try:
            # Вызываем функцию из api.py
            result = await api.run_osint_report(domain, wordlist_path="core/subdomains_wordlist.txt")
            
            console_output.controls.append(ft.Text("[+] Разведка завершена:", font_family="Courier New", color="#00e676"))
            
            if not result:
                console_output.controls.append(ft.Text("[-] Модуль вернул пустой результат.", font_family="Courier New", color="#ff1744"))
            elif "error" in result:
                console_output.controls.append(ft.Text(f"[-] Ошибка пайплайна: {result['error']}", font_family="Courier New", color="#ff1744"))
            else:
                # Сохраняем результаты в БД
                from datetime import datetime
                scan_time = result.get('scan_time') or datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                target_domain = result.get('domain', domain)
                whois_data = result.get('whois', {})
                registrar = whois_data.get('registrar') or whois_data.get('registrar_name') or whois_data.get('Регистратор') or 'Неизвестно'
                subdomains_count = len(result.get('subdomains', []))
                
                try:
                    database.save_osint_result(scan_time, target_domain, registrar, subdomains_count)
                    console_output.controls.append(ft.Text("[+] Результаты успешно сохранены в базу данных.", font_family="Courier New", color="#00e676"))
                except Exception as db_ex:
                    console_output.controls.append(ft.Text(f"[-] Ошибка保存в БД: {db_ex}", font_family="Courier New", color="#ff1744"))

                console_output.controls.append(ft.Text(f" -> Домен: {result.get('domain', domain)}", font_family="Courier New", color="#ffffff"))
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
        
        # ДОБАВЛЕНО: Разблокируем UI по завершении процесса
        start_btn.disabled = False
        progress_indicator.visible = False
        page.update()

    start_btn = ft.ElevatedButton(
        "Запустить анализ",
        icon=ft.Icons.SEARCH,
        bgcolor="#b388ff",
        color="#0b0813",
        on_click=start_osint_scan
    )

    # ИЗМЕНЕНО: Добавили progress_indicator в поисковую строку, чтобы лоадер крутился рядом с кнопкой
    search_row = ft.Row(controls=[domain_input, start_btn, progress_indicator], spacing=12, vertical_alignment=ft.CrossAxisAlignment.CENTER)

    results_box = ft.Container(
        content=ft.Column([
            ft.Text("Консоль вывода подсистемы разведки", size=14, color="#a7a2be"),
            ft.Divider(color="#251b45"),
            console_output
        ], spacing=8, expand=True),
        bgcolor="#18122b",
        padding=20,
        border_radius=12,
        border=ft.Border(
            top=ft.BorderSide(1, "#393053"),
            bottom=ft.BorderSide(1, "#393053"),
            left=ft.BorderSide(1, "#393053"),
            right=ft.BorderSide(1, "#393053")
        ),
        expand=True
    )

    return ft.Column(controls=[header, search_row, ft.Divider(color="#251b45"), results_box], expand=True, spacing=20)