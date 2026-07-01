import flet as ft
import api
import database
def network_page(page: ft.Page):
    header = ft.Text("Сетевой анализатор «Периметр»", size=28, weight=ft.FontWeight.BOLD, color="#ffffff")

    target_input = ft.TextField(
        label="IP-адрес, домен или подсеть CIDR",
        label_style=ft.TextStyle(color="#a7a2be", size=13),
        border_color="#393053",
        focused_border_color="#b388ff",
        bgcolor="#130f22",
        expand=True
    )

    results_list = ft.ListView(expand=True, spacing=10)

    async def start_scan_click(e):
        if not target_input.value:
            return
        
        results_list.controls.clear()
        results_list.controls.append(ft.Text("[*] Сканирование портов запущено...", color="#b388ff"))
        page.update() # ИСПРАВЛЕНО

        try:
            findings = await api.scan_network(target_input.value)
            results_list.controls.clear()

            if not findings or "error" in findings[0]:
                results_list.controls.append(ft.Text("[-] Ошибка сканирования или модуль недоступен", color="#ff1744"))
            else:
                # Сохраняем результаты в БД
                open_ports_count = len(findings)
                vulnerabilities_count = 0
                details = []
                
                for f in findings:
                    port_vulns = f.get("findings", [])
                    vulnerabilities_count += len(port_vulns)
                    
                    if not port_vulns:
                        details.append({
                            "port": f["port"],
                            "service": f["service"],
                            "banner": f["banner"],
                            "vulnerability_title": None,
                            "severity": None
                        })
                    else:
                        for vuln in port_vulns:
                            details.append({
                                "port": f["port"],
                                "service": f["service"],
                                "banner": f["banner"],
                                "vulnerability_title": vuln.get("title"),
                                "severity": vuln.get("severity")
                            })
                
                from datetime import datetime
                scan_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                try:
                    database.save_network_result(scan_time, target_input.value, open_ports_count, vulnerabilities_count, details)
                    results_list.controls.append(ft.Text("[+] Результаты успешно сохранены в базу данных.", color="#00e676"))
                except Exception as db_ex:
                    results_list.controls.append(ft.Text(f"[-] Ошибка сохранения в БД: {db_ex}", color="#ff1744"))

                for f in findings:
                    status_line = ft.Row([
                        ft.Icon(ft.Icons.RADIO_BUTTON_ON, color="#00e676", size=14),
                        ft.Text(f"Порт {f['port']} ({f['service']})", weight=ft.FontWeight.BOLD, color="#ffffff"),
                        ft.Text(f"Баннер: {f['banner']}" if f['banner'] else "", color="#a7a2be")
                    ])
                    results_list.controls.append(status_line)
                    
                    for vuln in f.get("findings", []):
                        vuln_line = ft.Text(f"    ↳ [!] {vuln.get('title', 'Уязвимость')} - {vuln.get('severity', 'UNKNOWN')}", color="#ff9100")
                        results_list.controls.append(vuln_line)
        except Exception as ex:
            results_list.controls.append(ft.Text(f"[-] Критическая ошибка: {ex}", color="#ff1744"))
        
        page.update() # ИСПРАВЛЕНО

    scan_btn = ft.ElevatedButton(
        "Сканировать",
        icon=ft.Icons.PLAY_ARROW,
        bgcolor="#b388ff",
        color="#0b0813",
        on_click=start_scan_click # Передаем асинхронную функцию напрямую
    )

    control_row = ft.Row([target_input, scan_btn], spacing=12)

    traffic_panel = ft.Container(
        content=ft.Column([
            ft.Text("Результаты сканирования сети в реальном времени:", size=16, weight=ft.FontWeight.W_500, color="#ffffff"),
            ft.Divider(color="#251b45"),
            results_list
        ], expand=True),
        bgcolor="#18122b",
        padding=20,
        border_radius=12,
        border=ft.Border.all(1, "#393053"),
        expand=True
    )

    return ft.Column(
        controls=[header, control_row, ft.Divider(color="#251b45"), traffic_panel],
        expand=True,
        spacing=20
    )