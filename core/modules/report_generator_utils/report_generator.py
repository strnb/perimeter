import sqlite3
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
import os
from pathlib import Path
from datetime import datetime

from database import DB_PATH

def register_fonts():
    """Кроссплатформенная регистрация шрифта DejaVuSans с поддержкой кириллицы."""
    try:
        # Пытаемся найти шрифт в папке assets относительно корня проекта
        font_path = Path(__file__).resolve().parents[3] / "assets" / "DejaVuSans.ttf"
        if not font_path.exists():
            # Альтернативный поиск от текущей рабочей директории
            font_path = Path("assets/DejaVuSans.ttf").resolve()
            
        pdfmetrics.registerFont(TTFont('DejaVuSans', str(font_path)))
    except Exception as e:
        print(f"[ERROR] Не удалось загрузить кастомный шрифт: {e}")
        # Фолбэк на базовый шрифт, если ничего не вышло (могут быть квадраты, но скрипт не упадет)
        pdfmetrics.registerFont(TTFont('DejaVuSans', 'Helvetica'))

def make_recommendation_box(text, style):
    """Создает красивую зеленую плашку для рекомендаций."""
    p = Paragraph(f"<b>Рекомендация по безопасности:</b><br/>{text}", style)
    t = Table([[p]], colWidths=[500])
    t.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,-1), colors.HexColor("#e8f5e9")),
        ('BOX', (0,0), (-1,-1), 1, colors.HexColor("#c8e6c9")),
        ('PADDING', (0,0), (-1,-1), 10),
        ('BOTTOMPADDING', (0,0), (-1,-1), 10),
    ]))
    return t

def generate_pdf_report(target_pdf_path):
    register_fonts()
    
    doc = SimpleDocTemplate(target_pdf_path, pagesize=letter, rightMargin=45, leftMargin=40, topMargin=45, bottomMargin=45)
    story = []
    
    # Кастомные стили с поддержкой кириллицы через DejaVuSans
    title_style = ParagraphStyle(
        'TitleStyle', fontName='DejaVuSans', fontSize=20, leading=26, textColor=colors.HexColor("#130f22"), spaceAfter=6, alignment=1
    )
    subtitle_style = ParagraphStyle(
        'SubtitleStyle', fontName='DejaVuSans', fontSize=10, leading=14, textColor=colors.HexColor("#555555"), spaceAfter=20, alignment=1
    )
    h1_style = ParagraphStyle(
        'H1Style', fontName='DejaVuSans', fontSize=14, leading=18, textColor=colors.HexColor("#1a1a1a"), spaceBefore=18, spaceAfter=10, keepWithNext=True
    )
    h2_style = ParagraphStyle(
        'H2Style', fontName='DejaVuSans', fontSize=11, leading=15, textColor=colors.HexColor("#251b45"), spaceBefore=12, spaceAfter=6, keepWithNext=True
    )
    body_style = ParagraphStyle(
        'BodyStyle', fontName='DejaVuSans', fontSize=9, leading=13, textColor=colors.HexColor("#333333"), spaceAfter=8
    )
    bullet_style = ParagraphStyle(
        'BulletStyle', fontName='DejaVuSans', fontSize=9, leading=13, textColor=colors.HexColor("#333333"), leftIndent=15, firstLineIndent=-10, spaceAfter=4
    )
    table_cell_style = ParagraphStyle(
        'TableCellStyle', fontName='DejaVuSans', fontSize=8, leading=11, textColor=colors.HexColor("#333333")
    )
    table_header_style = ParagraphStyle(
        'TableHeaderStyle', fontName='DejaVuSans', fontSize=8, leading=11, textColor=colors.whitesmoke, bold=True
    )
    
    # Подключаемся к БД
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    # Сбор статистики
    try:
        cursor.execute("SELECT COUNT(*), SUM(subdomains_count) FROM osint_results")
        osint_stats = cursor.fetchone()
        total_osint = osint_stats[0] or 0
        total_subdomains = osint_stats[1] or 0
    except:
        total_osint, total_subdomains = 0, 0

    try:
        cursor.execute("SELECT COUNT(*), SUM(critical_count), SUM(medium_count), SUM(low_count) FROM dlp_results")
        dlp_stats = cursor.fetchone()
        total_dlp = dlp_stats[0] if dlp_stats[0] else 0
        dlp_critical = dlp_stats[1] if dlp_stats[1] else 0
        dlp_medium = dlp_stats[2] if dlp_stats[2] else 0
        dlp_low = dlp_stats[3] if dlp_stats[3] else 0
    except:
        total_dlp, dlp_critical, dlp_medium, dlp_low = 0, 0, 0, 0

    try:
        cursor.execute("SELECT COUNT(*), SUM(open_ports_count), SUM(vulnerabilities_count) FROM network_results")
        net_stats = cursor.fetchone()
        total_net = net_stats[0] if net_stats[0] else 0
        net_ports = net_stats[1] if net_stats[1] else 0
        net_vulns = net_stats[2] if net_stats[2] else 0
    except:
        total_net, net_ports, net_vulns = 0, 0, 0

    # --- ТИТУЛЬНЫЙ ЛИСТ / ШАПКА ---
    story.append(Spacer(1, 20))
    story.append(Paragraph("КОМПЛЕКС АУДИТА БЕЗОПАСНОСТИ «ПЕРИМЕТР»", title_style))
    story.append(Paragraph("Сводный аналитический отчет по результатам комплексного исследования", subtitle_style))
    story.append(Spacer(1, 10))
    
    meta_headers = [Paragraph("Параметр", table_header_style), Paragraph("Значение", table_header_style)]
    meta_data = [
        meta_headers,
        [Paragraph("Дата генерации отчета", table_cell_style), Paragraph(datetime.now().strftime("%Y-%m-%d %H:%M:%S"), table_cell_style)],
        [Paragraph("Используемая СУБД", table_cell_style), Paragraph("SQLite 3 (perimeter.db)", table_cell_style)],
        [Paragraph("Статус аудита", table_cell_style), Paragraph("Завершен", table_cell_style)],
        [Paragraph("Класс системы", table_cell_style), Paragraph("Автоматизированный сканер защищенности", table_cell_style)]
    ]
    meta_table = Table(meta_data, colWidths=[180, 320])
    meta_table.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), colors.HexColor("#130f22")),
        ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor("#e0e0e0")),
        ('PADDING', (0,0), (-1,-1), 6),
        ('VALIGN', (0,0), (-1,-1), 'TOP'),
    ]))
    story.append(meta_table)
    story.append(Spacer(1, 20))
    
    # --- РАЗДЕЛ 1. СВОДНАЯ АНАЛИТИКА ---
    story.append(Paragraph("1. Сводная аналитика (Executive Summary)", h1_style))
    story.append(Paragraph(
        "Настоящий отчет содержит агрегированные результаты сканирования внешнего периметра, "
        "анализа локальных директорий на предмет утечек конфиденциальных данных (DLP) и сетевого аудита портов.",
        body_style
    ))
    
    stats_headers = [Paragraph("Модуль подсистемы", table_header_style), Paragraph("Всего сканирований", table_header_style), Paragraph("Обнаружено угроз / деталей", table_header_style)]
    stats_data = [
        stats_headers,
        [Paragraph("Внешняя разведка (OSINT)", table_cell_style), Paragraph(str(total_osint), table_cell_style), Paragraph(f"Найдено поддоменов в сумме: {total_subdomains}", table_cell_style)],
        [Paragraph("Мониторинг утечек (DLP)", table_cell_style), Paragraph(str(total_dlp), table_cell_style), Paragraph(f"Критических: {dlp_critical} | Средних: {dlp_medium} | Низких: {dlp_low}", table_cell_style)],
        [Paragraph("Сетевой анализатор (Network)", table_cell_style), Paragraph(str(total_net), table_cell_style), Paragraph(f"Открытых портов: {net_ports} | Уязвимостей: {net_vulns}", table_cell_style)]
    ]
    stats_table = Table(stats_data, colWidths=[180, 120, 200])
    stats_table.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), colors.HexColor("#251b45")),
        ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor("#e0e0e0")),
        ('PADDING', (0,0), (-1,-1), 6),
        ('VALIGN', (0,0), (-1,-1), 'TOP'),
    ]))
    story.append(stats_table)
    story.append(Spacer(1, 15))
    
    # --- РАЗДЕЛ 2. ВНЕШНЯЯ РАЗВЕДКА (OSINT) ---
    story.append(Paragraph("2. Результаты внешней разведки (OSINT)", h1_style))
    story.append(Paragraph("Подсистема OSINT осуществляет сбор информации из открытых источников без прямого воздействия на объект.", body_style))
    
    try:
        cursor.execute("SELECT scan_time, target_domain, registrar, subdomains_count FROM osint_results ORDER BY id DESC LIMIT 5")
        osint_data = cursor.fetchall()
    except:
        osint_data = []

    if osint_data:
        table_data = [[
            Paragraph("Время сканирования", table_header_style), 
            Paragraph("Целевой домен", table_header_style), 
            Paragraph("Регистратор", table_header_style), 
            Paragraph("Кол-во поддоменов", table_header_style)
        ]]
        for row in osint_data:
            table_data.append([
                Paragraph(str(row[0]), table_cell_style), 
                Paragraph(str(row[1]), table_cell_style), 
                Paragraph(str(row[2]), table_cell_style), 
                Paragraph(str(row[3]), table_cell_style)
            ])
        
        t = Table(table_data, colWidths=[120, 130, 150, 100])
        t.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,0), colors.HexColor("#130f22")),
            ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor("#e0e0e0")),
            ('PADDING', (0,0), (-1,-1), 6),
            ('VALIGN', (0,0), (-1,-1), 'TOP'),
        ]))
        story.append(t)
        story.append(Spacer(1, 10))
        story.append(make_recommendation_box(
            "1. Скройте персональные данные администратора домена в WHOIS.<br/>"
            "2. Настройте DNSSEC для защиты от подмены DNS-ответов.<br/>"
            "3. Регулярно проводите инвентаризацию поддоменов.",
            body_style
        ))
    else:
        story.append(Paragraph("Данные о внешнем сканировании отсутствуют (база пуста).", body_style))
        
    story.append(Spacer(1, 15))

    # --- РАЗДЕЛ 3. АНАЛИЗ УТЕЧЕК ДАННЫХ (DLP) ---
    story.append(Paragraph("3. Результаты анализа утечек данных (DLP)", h1_style))
    story.append(Paragraph("Модуль DLP предназначен для локального мониторинга исходного кода и конфигурационных файлов проекта на наличие секретов.", body_style))
    
    try:
        cursor.execute("SELECT scan_time, checked_path, critical_count, medium_count, low_count FROM dlp_results ORDER BY id DESC LIMIT 5")
        dlp_data = cursor.fetchall()
    except:
        dlp_data = []
    
    if dlp_data:
        table_data = [[
            Paragraph("Время", table_header_style), 
            Paragraph("Сканируемый путь", table_header_style), 
            Paragraph("Крит.", table_header_style), 
            Paragraph("Средн.", table_header_style), 
            Paragraph("Низк.", table_header_style)
        ]]
        for row in dlp_data:
            table_data.append([
                Paragraph(str(row[0]), table_cell_style), 
                Paragraph(str(row[1]), table_cell_style), 
                Paragraph(str(row[2]), table_cell_style), 
                Paragraph(str(row[3]), table_cell_style), 
                Paragraph(str(row[4]), table_cell_style)
            ])
            
        t = Table(table_data, colWidths=[110, 210, 60, 60, 60])
        t.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,0), colors.HexColor("#251b45")),
            ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor("#e0e0e0")),
            ('PADDING', (0,0), (-1,-1), 6),
            ('VALIGN', (0,0), (-1,-1), 'TOP'),
        ]))
        story.append(t)
        story.append(Spacer(1, 10))
        story.append(make_recommendation_box(
            "1. Никогда не храните пароли и API-токены в исходном коде.<br/>"
            "2. Добавьте файлы с секретами в файл .gitignore.<br/>"
            "3. В случае обнаружения утечки незамедлительно отзывайте скомпрометированные ключи.",
            body_style
        ))
    else:
        story.append(Paragraph("Данные локального DLP-мониторинга отсутствуют (база пуста).", body_style))

    story.append(Spacer(1, 15))

    # --- РАЗДЕЛ 4. СЕТЕВОЙ АУДИТ ---
    story.append(Paragraph("4. Результаты сетевого сканирования (Network)", h1_style))
    story.append(Paragraph("Сетевой анализатор осуществляет сканирование портов целевых хостов для определения активных сетевых служб.", body_style))
    
    try:
        cursor.execute("SELECT id, scan_time, target, open_ports_count, vulnerabilities_count FROM network_results ORDER BY id DESC LIMIT 5")
        network_data = cursor.fetchall()
    except:
        network_data = []

    if network_data:
        for net_row in network_data:
            result_id, scan_time, target, open_ports, vulns = net_row
            story.append(Paragraph(f"<b>Цель сканирования:</b> {target} | <b>Время:</b> {scan_time} | <b>Открытых портов:</b> {open_ports} | <b>Уязвимостей:</b> {vulns}", h2_style))
            story.append(Spacer(1, 4))
            
            cursor.execute("SELECT port, service, banner, vulnerability_title, severity FROM network_details WHERE result_id = ?", (result_id,))
            details = cursor.fetchall()
            
            if details:
                table_data = [[
                    Paragraph("Порт", table_header_style), 
                    Paragraph("Служба", table_header_style), 
                    Paragraph("Баннер", table_header_style), 
                    Paragraph("Уязвимость", table_header_style), 
                    Paragraph("Риск", table_header_style)
                ]]
                for d_row in details:
                    port, service, banner, vuln_title, severity = d_row
                    table_data.append([
                        Paragraph(str(port), table_cell_style), 
                        Paragraph(str(service), table_cell_style), 
                        Paragraph(str(banner if banner else "-"), table_cell_style), 
                        Paragraph(str(vuln_title if vuln_title else "-"), table_cell_style), 
                        Paragraph(str(severity if severity else "-"), table_cell_style)
                    ])
                
                t = Table(table_data, colWidths=[50, 80, 120, 180, 70])
                t.setStyle(TableStyle([
                    ('BACKGROUND', (0,0), (-1,0), colors.HexColor("#393053")),
                    ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor("#e0e0e0")),
                    ('PADDING', (0,0), (-1,-1), 5),
                    ('VALIGN', (0,0), (-1,-1), 'TOP'),
                ]))
                story.append(t)
                story.append(Spacer(1, 8))
        
        story.append(make_recommendation_box(
            "1. Закройте неиспользуемые порты на внешнем сетевом интерфейсе с помощью брандмауэра.<br/>"
            "2. Отключите передачу подробных версий ПО в баннерах ответов служб.<br/>"
            "3. Регулярно обновляйте системное ПО и сетевые службы.",
            body_style
        ))
    else:
        story.append(Paragraph("Данные сетевого сканирования отсутствуют (база пуста).", body_style))

    story.append(Spacer(1, 15))
    
    # --- РАЗДЕЛ 5. ЗАКЛЮЧЕНИЕ ---
    story.append(Paragraph("5. Заключение и приоритетный план действий", h1_style))
    
    story.append(Paragraph("<b>[Приоритет 1 - КРИТИЧЕСКИЙ]</b> Локализовать и устранить все утечки секретов, обнаруженные модулем DLP.", bullet_style))
    story.append(Paragraph("<b>[Приоритет 2 - ВЫСОКИЙ]</b> Настроить правила межсетевого экрана для ограничения доступа к административным портам.", bullet_style))
    story.append(Paragraph("<b>[Приоритет 3 - СРЕДНИЙ]</b> Обновить версии ПО на сетевых службах, для которых были обнаружены известные уязвимости.", bullet_style))
    story.append(Paragraph("<b>[Приоритет 4 - НИЗКИЙ]</b> Провести аудит DNS-записей и WHOIS-информации доменных имен организации.", bullet_style))
    
    story.append(Spacer(1, 15))
    story.append(Paragraph("<i>Отчет сформирован автоматически и предназначен исключительно для внутреннего использования техническими специалистами.</i>", body_style))

    conn.close()
    doc.build(story)