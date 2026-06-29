import flet as ft

def network_page(page: ft.Page):
    header = ft.Text("Сетевой анализатор «Периметр»", size=28, weight=ft.FontWeight.BOLD, color="#ffffff")

    def create_stat_card(title, value, icon_name, neon_color):
        return ft.Container(
            content=ft.Row(
                controls=[
                    ft.Icon(icon_name, color=neon_color, size=26),
                    ft.Column(
                        controls=[
                            ft.Text(title, size=11, color="#a7a2be"),
                            ft.Text(value, size=16, weight=ft.FontWeight.BOLD, color="#ffffff")
                        ],
                        spacing=1,
                        alignment=ft.MainAxisAlignment.CENTER
                    )
                ],
                spacing=12
            ),
            bgcolor="#18122b",
            padding=15,
            border_radius=10,
            width=230,
            height=75,
            border=ft.Border.all(1, "#393053")
        )

    network_stats = ft.Row(
        controls=[
            create_stat_card("Шлюз WireGuard", "Активен", ft.Icons.SHIELD, "#00e676"),
            create_stat_card("Интерфейс туннеля", "perimeter-tun", ft.Icons.ROUTER, "#b388ff"), 
            create_stat_card("Задержка сети", "42 мс", ft.Icons.SPEED, "#ffea00"),
        ],
        spacing=15
    )

    traffic_panel = ft.Container(
        content=ft.Column(
            controls=[
                ft.Row([
                    ft.Text("Конфикагурация интерфейсов ядра", size=16, weight=ft.FontWeight.W_500, color="#ffffff"),
                    ft.IconButton(ft.Icons.REFRESH, icon_size=18, icon_color="#b388ff")
                ], alignment=ft.MainAxisAlignment.SPACE_BETWEEN),
                ft.Divider(color="#251b45"),
                ft.Row([ft.Text("eth0", weight=ft.FontWeight.BOLD, color="#ffffff"), ft.Text("192.168.1.45", color="#a7a2be"), ft.Text("UP", color="#00e676")]),
                ft.Row([ft.Text("perimeter-tun", weight=ft.FontWeight.BOLD, color="#b388ff"), ft.Text("10.0.0.2", color="#a7a2be"), ft.Text("RUNNING", color="#00e676")]),
            ],
            spacing=12
        ),
        bgcolor="#18122b",
        padding=20,
        border_radius=12,
        border=ft.Border.all(1, "#393053"),
        expand=True
    )

    return ft.Column(
        controls=[header, network_stats, ft.Divider(color="#251b45"), traffic_panel],
        expand=True,
        spacing=20
    )