import flet as ft

def dashboard_page(page: ft.Page):

    # 1. ШАБЛОН ДЛЯ ИНДЕКСА БЕЗОПАСНОСТИ (Security Index)
    # Создаем контейнер-карточку
    security_card = ft.Container(
        content=ft.Column(
            controls=[
                ft.Text("Индекс Безопасности", size=16, color=ft.Colors.GREY_400),
                ft.Text("100", size=48, weight=ft.FontWeight.BOLD, color=ft.Colors.GREEN) # Цифра 100 зеленого цвета
            ],
            spacing=5 # spacing (отступ между заголовком и цифрой)
        ),
        bgcolor=ft.Colors.ON_SURFACE_VARIANT, # bgcolor (цвет фона карточки)
        padding=20,                           # padding (внутренние отступы)
        border_radius=10,                     # border_radius (скругление углов)
        width=300,                            # width (ширина карточки)
    )

    # 2. ШАБЛОН ДЛЯ СЧЁТЧИКОВ УГРОЗ (Threat Counter)
    # Функция для быстрой сборки маленьких плиток
    def create_badge(label, value, border_color):
        return ft.Container(
            content=ft.Column(
                controls=[
                    ft.Text(label, size=12, color=ft.Colors.GREY_400, weight=ft.FontWeight.W_500),
                    ft.Text(value, size=24, weight=ft.FontWeight.BOLD)
                ],
                spacing=2 # spacing (отступ между словом и цифрой)
            ),
            bgcolor=ft.Colors.ON_SURFACE_VARIANT, 
            padding=15,                           
            border_radius=8,                      
            width=140,                            
            height=80,                            # height (фиксированная высота, чтобы не сжималась)
            border=ft.Border.all(1, border_color) # border (цветная рамка: красная, оранжевая или желтая)
        )

    # Собираем три плитки в один горизонтальный ряд
    counters_row = ft.Row(
        controls=[
            create_badge("Критических", "3", ft.Colors.RED_ACCENT_700),
            create_badge("Средних", "12", ft.Colors.ORANGE_ACCENT_400),
            create_badge("Низких", "5", ft.Colors.YELLOW_ACCENT_400),
        ],
        spacing=15, # spacing (расстояние между плитками в ряду)
        alignment=ft.MainAxisAlignment.START # выравнивание ряда по левому краю
    )

    # 3. ГЛАВНАЯ СТРУКТУРА СТРАНИЦЫ
    # Собираем всё в одну вертикальную колонку
    return ft.Column(
        controls=[
            ft.Text("Dashboard", size=28, weight=ft.FontWeight.BOLD), # Крупный заголовок страницы
            ft.Divider(), # Линия-разделитель под заголовком
            security_card, # Карточка с сотней
            counters_row,  # Ряд с цветными плитками под ней
        ],
        alignment=ft.MainAxisAlignment.START,
        spacing=20 # spacing (расстояние между заголовком, линией, индексом и счетчиками)
    )