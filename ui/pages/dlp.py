import flet as ft
import api

def dlp_page(page: ft.Page):
    header = ft.Text("Мониторинг DLP", size=28, weight=ft.FontWeight.BOLD, color="#ffffff")

    path_input = ft.TextField(
        label="Путь к сканируемой директории проекта",
        label_style=ft.TextStyle(color="#a7a2be", size=13),
        border_color="#393053",
        focused_border_color="#b388ff",
        bgcolor="#130f22",
        expand=True,
        value="."
    )

    # Расширяем таблицу новыми колонками: Строка и Содержимое
    incidents_table = ft.DataTable(
        bgcolor="#18122b",
        border_radius=10,
        heading_row_color="#130f22",
        border=ft.Border.all(1, "#393053"),
        columns=[
            ft.DataColumn(ft.Text("Тип нарушения", weight=ft.FontWeight.BOLD, color="#b388ff")),
            ft.DataColumn(ft.Text("Файл / Источник", weight=ft.FontWeight.BOLD, color="#b388ff")),
            ft.DataColumn(ft.Text("№ Строки", weight=ft.FontWeight.BOLD, color="#b388ff")),
            ft.DataColumn(ft.Text("Проблемные данные", weight=ft.FontWeight.BOLD, color="#b388ff")),
            ft.DataColumn(ft.Text("Уровень риска", weight=ft.FontWeight.BOLD, color="#b388ff")),
        ],
        rows=[]
    )

    async def start_dlp_scan(e):
        incidents_table.rows.clear()
        page.update()

        try:
            raw_findings = api.scan_dlp(path_input.value)
            
            if not raw_findings:
                incidents_table.rows.append(
                    ft.DataRow(cells=[
                        ft.DataCell(ft.Text("Угрозы не обнаружены", color="#00e676")),
                        ft.DataCell(ft.Text("-")),
                        ft.DataCell(ft.Text("-")),
                        ft.DataCell(ft.Text("-")),
                        ft.DataCell(ft.Text("-"))
                    ])
                )
            elif "error" in raw_findings[0]:
                incidents_table.rows.append(
                    ft.DataRow(cells=[
                        ft.DataCell(ft.Text("Ошибка модуля DLP", color="#ff1744")),
                        ft.DataCell(ft.Text(raw_findings[0]["error"])),
                        ft.DataCell(ft.Text("-")),
                        ft.DataCell(ft.Text("-")),
                        ft.DataCell(ft.Text("CRITICAL", color="#ff1744"))
                    ])
                )
            else:
                for f in raw_findings:
                    # Вытаскиваем тип, файл и критичность
                    vuln_type = f.get("type") or f.get("vuln_type", "Неизвестно")
                    file_src = f.get("file", "Лог")
                    severity = f.get("severity", "LOW").upper()
                    
                    # Извлекаем номер строки и само содержимое (проблемный кусок кода)
                    line_num = str(f.get("line", "?"))
                    # Бывает raw_line, code, match или value. На всякий случай проверяем популярные ключи:
                    problem_data = f.get("raw_line") or f.get("match") or f.get("value") or "Секретные данные"

                    color = "#ff1744" if severity in ("CRITICAL", "HIGH") else "#ff9100"

                    incidents_table.rows.append(
                        ft.DataRow(cells=[
                            ft.DataCell(ft.Text(vuln_type, color="#ffffff")),
                            ft.DataCell(ft.Text(file_src, color="#a7a2be")),
                            ft.DataCell(ft.Text(line_num, color="#ffffff")),
                            # Оборачиваем в Container, чтобы длинный секрет/пароль аккуратно смотрелся
                            ft.DataCell(ft.Container(
                                content=ft.Text(problem_data, color="#ffeb3b", font_family="Courier New", size=12),
                                width=250,
                                alignment=ft.alignment.center_left
                            )),
                            ft.DataCell(ft.Text(severity, color=color)),
                        ])
                    )
        except Exception as ex:
            incidents_table.rows.append(
                ft.DataRow(cells=[
                    ft.DataCell(ft.Text("Критический сбой", color="#ff1744")),
                    ft.DataCell(ft.Text(str(ex))),
                    ft.DataCell(ft.Text("-")),
                    ft.DataCell(ft.Text("-")),
                    ft.DataCell(ft.Text("FAIL"))
                ])
            )
        
        page.update()

    scan_btn = ft.ElevatedButton(
        "Анализ директории",
        icon=ft.Icons.FIND_IN_PAGE,
        bgcolor="#b388ff",
        color="#0b0813",
        on_click=start_dlp_scan
    )

    search_row = ft.Row(controls=[path_input, scan_btn], spacing=12)

    return ft.Column(
        controls=[
            header,
            ft.Text("Настройка области сканирования DLP-модуля:", size=14, color="#a7a2be"),
            search_row,
            ft.Divider(color="#251b45"),
            ft.Text("Обнаруженные инциденты и утечки данных:", size=16, weight=ft.FontWeight.W_500, color="#ffffff"),
            # Оборачиваем в Row с возможностью скролла, если таблица не влезет по ширине
            ft.Row([
                ft.ListView(controls=[incidents_table], expand=True)
            ], expand=True, scroll=ft.ScrollMode.ADAPTIVE)
        ],
        expand=True,
        spacing=20
    )