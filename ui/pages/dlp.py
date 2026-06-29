import flet as ft

def dlp_page(page: ft.Page):
    header = ft.Text("Мониторинг DLP", size=28, weight=ft.FontWeight.BOLD, color="#ffffff")

    def create_channel_status(name, is_active):
        return ft.Container(
            content=ft.Row(
                controls=[
                    ft.Icon(
                        ft.Icons.CHECK_CIRCLE if is_active else ft.Icons.CANCEL,
                        color="#00e676" if is_active else "#ff1744",
                        size=18
                    ),
                    ft.Text(name, size=13, weight=ft.FontWeight.W_500, color="#ffffff")
                ],
                spacing=8
            ),
            bgcolor="#18122b",
            padding=12,
            border_radius=8,
            width=190,
            border=ft.Border.all(1, "#393053") 
        )

    channels_row = ft.Row(
        controls=[
            create_channel_status("Контроль USB", True),
            create_channel_status("Сетевой трафик", True),
            create_channel_status("Буфер обмена", True),
        ],
        spacing=15
    )

    incidents_table = ft.DataTable(
        bgcolor="#18122b",
        border_radius=10,
        heading_row_color="#130f22",
        border=ft.Border.all(1, "#393053"), 
        horizontal_lines=ft.BorderSide(0.5, "#251b45"), 
        columns=[
            ft.DataColumn(ft.Text("Время", weight=ft.FontWeight.BOLD, color="#b388ff")),
            ft.DataColumn(ft.Text("Пользователь", weight=ft.FontWeight.BOLD, color="#b388ff")),
            ft.DataColumn(ft.Text("Канал", weight=ft.FontWeight.BOLD, color="#b388ff")),
            ft.DataColumn(ft.Text("Файл / Данные", weight=ft.FontWeight.BOLD, color="#b388ff")),
            ft.DataColumn(ft.Text("Статус", weight=ft.FontWeight.BOLD, color="#b388ff")),
        ],
        rows=[
            ft.DataRow(cells=[
                ft.DataCell(ft.Text("15:42:11")), ft.DataCell(ft.Text("Иванов И.И.")),
                ft.DataCell(ft.Text("USB-накопитель")), ft.DataCell(ft.Text("report_2026.xlsx", color="#ff5252")),
                ft.DataCell(ft.Text("Заблокировано", color="#ff1744")),
            ]),
            ft.DataRow(cells=[
                ft.DataCell(ft.Text("14:15:03")), ft.DataCell(ft.Text("Петров П.П.")),
                ft.DataCell(ft.Text("Web (Браузер)")), ft.DataCell(ft.Text("Паспортные_данные.txt")),
                ft.DataCell(ft.Text("Предупреждение", color="#ff9100")),
            ]),
        ]
    )

    return ft.Column(
        controls=[
            header,
            ft.Text("Активные модули защиты:", size=14, color="#a7a2be"),
            channels_row,
            ft.Divider(color="#251b45"),
            ft.Text("Журнал нарушений политик безопасности:", size=16, weight=ft.FontWeight.W_500, color="#ffffff"),
            ft.ListView(controls=[incidents_table], expand=True)
        ],
        expand=True,
        spacing=20
    )