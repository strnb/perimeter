import logging
import flet as ft
import api
import asyncio
import database
from pathlib import Path
import os

logger = logging.getLogger(__name__)

COL_FLEX = {
    "type": 2,
    "file": 3,
    "line": 1,
    "data": 4,
    "severity": 2,
}

def dlp_page(page: ft.Page):
    header = ft.Text("Мониторинг DLP", size=28, weight=ft.FontWeight.BOLD, color="#ffffff")

    path_input = ft.TextField(
        label="Путь к сканируемой директории проекта",
        label_style=ft.TextStyle(color="#a7a2be", size=13),
        border_color="#393053",
        focused_border_color="#b388ff",
        bgcolor="#130f22",
        expand=True,
        value=""
    )

    def table_row(cells_text, cells_color=None, header_row=False):
        cells_color = cells_color or ["#ffffff"] * len(cells_text)
        keys = ["type", "file", "line", "data", "severity"]
        controls = []
        for key, text, color in zip(keys, cells_text, cells_color):
            controls.append(
                ft.Container(
                    content=ft.Text(
                        text,
                        color=color,
                        weight=ft.FontWeight.BOLD if header_row else None,
                        size=13,
                        font_family="Courier New" if key == "data" and not header_row else None,
                        no_wrap=False,
                    ),
                    expand=COL_FLEX[key],
                    padding=ft.Padding(8, 10, 8, 10),
                )
            )
        return ft.Container(
            content=ft.Row(controls=controls, vertical_alignment=ft.CrossAxisAlignment.START, spacing=0),
            bgcolor="#130f22" if header_row else None,
            border=ft.Border(bottom=ft.BorderSide(0.5, "#393053")),
        )

    table_header = table_row(
        ["Тип нарушения", "Файл / Источник", "№ Строки", "Проблемные данные", "Уровень риска"],
        cells_color=["#b388ff"] * 5,
        header_row=True,
    )

    table_rows_column = ft.Column(controls=[], spacing=0)

    incidents_table = ft.Container(
        content=ft.Column(
            controls=[table_header, table_rows_column],
            spacing=0,
        ),
        bgcolor="#18122b",
        border_radius=10,
        border=ft.Border(
            top=ft.BorderSide(0.5, "#393053"),
            bottom=ft.BorderSide(0.5, "#393053"),
            left=ft.BorderSide(0.5, "#393053"),
            right=ft.BorderSide(0.5, "#393053")
        ),
        clip_behavior=ft.ClipBehavior.ANTI_ALIAS,
    )

    loading_indicator = ft.ProgressBar(width=400, color="#b388ff", bgcolor="#393053", visible=False)

    async def start_dlp_scan(e):
        path_str = path_input.value.strip() if path_input.value else ""

        # 1. Проверка на пустое значение
        if not path_str:
            snack = ft.SnackBar(
                content=ft.Text("Ошибка: Путь к директории не может быть пустым!"), 
                bgcolor="#b71c1c"
            )
            page.overlay.append(snack)
            snack.open = True
            page.update()
            return
        # 2. Безопасность путей (Защита от Path Traversal и сканирования критических зон)
        try:
            target_path = Path(path_str).resolve()
            project_root = Path(os.getcwd()).resolve()
            home_dir = Path.home().resolve()
            
            # Разрешаем сканирование только если путь находится внутри папки проекта или домашней папки юзера
            is_inside_project = project_root in target_path.parents or target_path == project_root
            is_inside_home = home_dir in target_path.parents or target_path == home_dir
            
            if not (is_inside_project or is_inside_home):
                snack = ft.SnackBar(
                    content=ft.Text("Ошибка безопасности: Разрешено сканировать только директории проекта или пользователя!"),
                    bgcolor="#b71c1c"
                )
                page.overlay.append(snack)
                snack.open = True
                page.update()
                return
        except Exception as path_ex:
            snack = ft.SnackBar(content=ft.Text(f"Недопустимый формат пути: {path_ex}"), bgcolor="#b71c1c")
            page.overlay.append(snack)
            snack.open = True
            page.update()
            return
        print(f"[DEBUG] Запуск сканирования: {path_str}")
        logger.info(f"Запуск DLP сканирования для пути: {path_str}")
        loading_indicator.visible = True
        table_rows_column.controls.clear()
        page.update()

        try:
            raw_findings = await asyncio.to_thread(api.scan_dlp, path_str)
            print(f"[DEBUG] Найдено результатов: {len(raw_findings)}")
            logger.info(f"Сканирование завершено. Найдено находок: {len(raw_findings)}")

            if raw_findings and "error" not in raw_findings[0]:
                critical_count = 0
                medium_count = 0
                low_count = 0
                for f in raw_findings:
                    severity = f.get("severity", "LOW").upper()
                    if severity in ("CRITICAL", "HIGH"):
                        critical_count += 1
                    elif severity == "MEDIUM":
                        medium_count += 1
                    else:
                        low_count += 1
                
                from datetime import datetime
                scan_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                try:
                    database.save_dlp_result(scan_time, path_str, critical_count, medium_count, low_count)
                    logger.info("Результаты DLP успешно сохранены в БД.")
                except Exception as db_ex:
                    logger.error(f"Ошибка сохранения результатов DLP в БД: {db_ex}")

            if not raw_findings:
                table_rows_column.controls.append(
                    table_row(["Угрозы не обнаружены", "-", "-", "-", "-"],
                              cells_color=["#00e676", "#a7a2be", "#ffffff", "#ffeb3b", "#ffffff"])
                )
            elif "error" in raw_findings[0]:
                table_rows_column.controls.append(
                    table_row(
                        ["Ошибка модуля DLP", raw_findings[0]["error"], "-", "-", "CRITICAL"],
                        cells_color=["#ff1744", "#a7a2be", "#ffffff", "#ffeb3b", "#ff1744"]
                    )
                )
            else:
                for f in raw_findings:
                    vuln_type = f.get("type") or f.get("vuln_type", "Неизвестно")
                    file_src = f.get("file", "Лог")
                    severity = f.get("severity", "LOW").upper()
                    line_num = str(f.get("line", "?"))
                    problem_data = f.get("raw_line") or f.get("match") or f.get("value") or "Секретные данные"

                    color = "#ff1744" if severity in ("CRITICAL", "HIGH") else "#ff9100"

                    if line_num == "0":
                        table_rows_column.controls.append(
                            table_row(
                                [vuln_type, file_src, "-", problem_data, severity],
                                cells_color=["#ffffff", "#a7a2be", "#ffffff", "#ffeb3b", color]
                            )
                        )
                    else:
                        table_rows_column.controls.append(
                            table_row(
                                [vuln_type, file_src, line_num, problem_data, severity],
                                cells_color=["#ffffff", "#a7a2be", "#ffffff", "#ffeb3b", color]
                            )
                        )
        except Exception as ex:
            logger.error(f"Ошибка при выполнении DLP сканирования: {ex}", exc_info=True)
            table_rows_column.controls.append(
                table_row(["Критический сбой", str(ex), "-", "-", "FAIL"],
                          cells_color=["#ff1744", "#a7a2be", "#ffffff", "#ffeb3b", "#ff1744"])
            )
        finally:
            loading_indicator.visible = False
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
            loading_indicator,
            ft.Divider(color="#251b45"),
            ft.Text("Обнаруженные инциденты и утечки данных:", size=16, weight=ft.FontWeight.W_500, color="#ffffff"),

            ft.Container(
                content=ft.Column(
                    controls=[incidents_table],
                    scroll=ft.ScrollMode.ALWAYS,
                    expand=True,
                ),
                height=420,
                expand=True,
                padding=5,
            )
        ],
        expand=True,
        spacing=20
    )