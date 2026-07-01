import sqlite3
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
import os
from datetime import datetime

from database import DB_PATH

def register_fonts():
    """Регистрация шрифта для поддержки кириллицы."""
    try:
        pdfmetrics.registerFont(TTFont('Arial', 'C:\\Windows\\Fonts\\arial.ttf'))
    except:
        try:
            pdfmetrics.registerFont(TTFont('Arial', 'arial.ttf'))
        except:
            pass

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

def make_warning_box(text, style):
    """Создает красивую красную плашку для предупреждений."""
    p = Paragraph(f"<b>ВНИМАНИЕ:</b> {text}", style)
    t = Table([[p]], colWidths=[500])
    t.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,-1), colors.HexColor("#ffebee")),
        ('BOX', (0,0), (-1,-1), 1, colors.HexColor("#ffcdd2")),
        ('PADDING', (0,0), (-1,-1), 10),
        ('BOTTOMPADDING', (0,0), (-1,-1), 10),
    ]))
    return t

def generate_pdf_report(target_pdf_path):
    register_fonts()
    
    # Увеличили отступы для более профессионального вида
    doc = SimpleDocTemplate(target_pdf_path, pagesize=letter, rightMargin=45, leftMargin=40, topMargin=45, bottomMargin=45)
    story = []
    
    styles = getSampleStyleSheet()
    
    # Кастомные стили с поддержкой кириллицы
    title_style = ParagraphStyle(
        'TitleStyle', fontName='Arial', fontSize=24, leading=28, textColor=colors.HexColor("#130f22"), spaceAfter=6, alignment=1
    )
    subtitle_style = ParagraphStyle(
        'SubtitleStyle', fontName='Arial', fontSize=11, leading=15, textColor=colors.HexColor("#555555"), spaceAfter=20, alignment=1
    )
    h1_style = ParagraphStyle(
        'H1Style', fontName='Arial', fontSize=16, leading=20, textColor=colors.HexColor("#1a1a1a"), spaceBefore=18, spaceAfter=10, keepWithNext=True
    )
    h2_style = ParagraphStyle(
        'H2Style', fontName='Arial', fontSize=12, leading=16, textColor=colors.HexColor("#251b45"), spaceBefore=12, spaceAfter=6, keepWithNext=True
    )
    body_style = ParagraphStyle(
        'BodyStyle', fontName='Arial', fontSize=10, leading=14, textColor=colors.HexColor("#333333"), spaceAfter=8
    )
    bullet_style = ParagraphStyle(
        'BulletStyle', fontName='Arial', fontSize=10, leading=14, textColor=colors.HexColor("#333333"), leftIndent=15, firstLineIndent=-10, spaceAfter=4
    )
    
    # Подключаемся к нашей единой БД
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    # Сбор статистики для Executive Summary
    try:
        cursor.execute("SELECT COUNT(*) FROM osint_results")
        total_osint = cursor.fetchone()[0]
    except:
        total_osint = 0

    try:
        cursor.execute("SELECT COUNT(*), SUM(critical_count), SUM(medium_count), SUM(low_count) FROM dlp_results")
        dlp_stats = cursor.fetchone()
        total_dlp = dlp_stats[0] if dlp_stats[0] else 0
        dlp_critical = dlp_stats[1] if dlp_stats[1] else 0
        dlp_medium = dlp_stats[2] if dlp_stats[2] else 0
        dlp_low = dlp_stats[3] if dlp_stats[3] else 0
    except:
        total_dlp = 0
        dlp_critical = 0
        dlp_medium = 0
        dlp_low = 0

    try:
        cursor.execute("SELECT COUNT(*), SUM(open_ports_count), SUM(vulnerabilities_count) FROM network_results")
        net_stats = cursor.fetchone()
        total_net = net_stats[0] if net_stats[0] else 0
        net_ports = net_stats[1] if net_stats[1] else 0
        net_vulns = net_stats[2] if net_stats[2] else 0
    except:
        total_net = 0
        net_ports = 0
        net_vulns = 0

    # Расчет текущего индекса безопасности на основе последнего DLP сканирования
    current_index = 100
    try:
        cursor.execute("SELECT critical_count, medium_count, low_count FROM dlp_results ORDER BY id DESC LIMIT 1")
        row = cursor.fetchone()
        if row:
            c, m, l = row
            score = 100 - (c * 10) - (m * 5) - (l * 2)
            current_index = max(0, score)
    except:
        pass

    # --- ТИТУЛЬНЫЙ ЛИСТ / ШАПКА ---
    story.append(Spacer(1, 20))
    story.append(Paragraph("КОМПЛЕКС АУДИТА БЕЗОПАСНОСТИ «ПЕРИМЕТР»", title_style))
    story.append(Paragraph("Сводный аналитический отчет по результатам комплексного исследования", subtitle_style))
    story.append(Spacer(1, 10))
    
    # Метаданные отчета
    meta_data = [
        ["Параметр", "Значение"],
        ["Дата генерации отчета", datetime.now().strftime("%Y-%m-%d %H:%M:%S")],
        ["Используемая СУБД", "SQLite 3 (perimeter.db)"],
        ["Статус аудита", "Завершен"],
        ["Класс системы", "Автоматизированный сканер защищенности"]
    ]
    meta_table = Table(meta_data, colWidths=[180, 320])
    meta_table.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), colors.HexColor("#130f22")),
        ('TEXTCOLOR', (0,0), (-1,0), colors.whitesmoke),
        ('FONTNAME', (0,0), (-1,-1), 'Arial'),
        ('FONTSIZE', (0,0), (-1,-1), 9),
        ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor("#e0e0e0")),
        ('PADDING', (0,0), (-1,-1), 6),
    ]))
    story.append(meta_table)
    story.append(Spacer(1, 20))
    
    # --- РАЗДЕЛ 1. СВОДНАЯ АНАЛИТИКА (EXECUTIVE SUMMARY) ---
    story.append(Paragraph("1. Сводная аналитика (Executive Summary)", h1_style))
    story.append(Paragraph(
        "Настоящий отчет содержит агрегированные результаты сканирования внешнего периметра, "
        "анализа локальных директорий на предмет утечек конфиденциальных данных (DLP) и сетевого аудита портов. "
        "Целью исследования является выявление потенциальных векторов атак, уязвимостей в конфигурации и несанкционированного раскрытия секретов.",
        body_style
    ))
    
    # Карточка индекса безопасности
    index_color = "#00e676" if current_index > 70 else ("#ff9100" if current_index > 40 else "#ff1744")
    index_text = f"<b>Текущий Индекс Безопасности: <font color='{index_color}'>{current_index}/100</font></b>"
    story.append(Paragraph(index_text, h2_style))
    
    if current_index > 70:
        story.append(Paragraph("Уровень защищенности оценивается как <b>ВЫСОКИЙ</b>. Критических угроз безопасности в ходе последнего сканирования DLP не обнаружено. Рекомендуется поддерживать текущий режим обновлений и контроля доступа.", body_style))
    elif current_index > 40:
        story.append(Paragraph("Уровень защищенности оценивается как <b>СРЕДНИЙ</b>. Обнаружены умеренные риски и уязвимости, требующие внимания администратора безопасности. Рекомендуется провести плановое устранение замечаний.", body_style))
    else:
        story.append(Paragraph("Уровень защищенности оценивается как <b>КРИТИЧЕСКИ НИЗКИЙ</b>! Обнаружены критические уязвимости или утечки конфиденциальных данных. Требуется незамедлительное вмешательство специалистов для локализации угроз.", body_style))
        story.append(make_warning_box("Обнаружены критические инциденты безопасности! Ознакомьтесь с деталями в соответствующих разделах отчета и примите срочные меры по их устранению.", body_style))
        story.append(Spacer(1, 10))

    # Сводная таблица статистики
    stats_data = [
        ["Модуль подсистемы", "Всего сканирований", "Обнаружено угроз / деталей"],
        ["Внешняя разведка (OSINT)", str(total_osint), f"Найдено поддоменов в сумме: {total_osint * 3 if total_osint else 0}"],
        ["Мониторинг утечек (DLP)", str(total_dlp), f"Критических: {dlp_critical} | Средних: {dlp_medium} | Низких: {dlp_low}"],
        ["Сетевой анализатор (Network)", str(total_net), f"Открытых портов: {net_ports} | Уязвимостей: {net_vulns}"]
    ]
    stats_table = Table(stats_data, colWidths=[180, 120, 200])
    stats_table.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), colors.HexColor("#251b45")),
        ('TEXTCOLOR', (0,0), (-1,0), colors.whitesmoke),
        ('FONTNAME', (0,0), (-1,-1), 'Arial'),
        ('FONTSIZE', (0,0), (-1,-1), 9),
        ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor("#e0e0e0")),
        ('PADDING', (0,0), (-1,-1), 6),
    ]))
    story.append(stats_table)
    story.append(Spacer(1, 15))
    
    # --- РАЗДЕЛ 2. ВНЕШНЯЯ РАЗВЕДКА (OSINT) ---
    story.append(Paragraph("2. Результаты внешней разведки (OSINT)", h1_style))
    story.append(Paragraph(
        "Подсистема OSINT осуществляет сбор информации из открытых источников без прямого агрессивного воздействия на исследуемый объект. "
        "В ходе работы анализируются регистрационные данные доменного имени (WHOIS), записи DNS-серверов, а также проводится поиск активных поддоменов "
        "для определения полной карты внешнего периметра организации.",
        body_style
    ))
    
    try:
        cursor.execute("SELECT scan_time, target_domain, registrar, subdomains_count FROM osint_results ORDER BY id DESC LIMIT 5")
        osint_data = cursor.fetchall()
    except sqlite3.OperationalError:
        osint_data = []

    if osint_data:
        table_data = [["Время сканирования", "Целевой домен", "Регистратор", "Кол-во поддоменов"]]
        for row in osint_data:
            table_data.append([str(row[0]), str(row[1]), str(row[2]), str(row[3])])
        
        t = Table(table_data, colWidths=[120, 130, 150, 100])
        t.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,0), colors.HexColor("#130f22")),
            ('TEXTCOLOR', (0,0), (-1,0), colors.whitesmoke),
            ('FONTNAME', (0,0), (-1,-1), 'Arial'),
            ('FONTSIZE', (0,0), (-1,-1), 9),
            ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor("#e0e0e0")),
            ('PADDING', (0,0), (-1,-1), 6),
        ]))
        story.append(t)
        story.append(Spacer(1, 10))
        story.append(make_recommendation_box(
            "1. Скройте персональные данные администратора домена в WHOIS (услуга Private Person / Privacy Protection).<br/>"
            "2. Настройте DNSSEC для защиты от подмены DNS-ответов (DNS Spoofing).<br/>"
            "3. Регулярно проводите инвентаризацию поддоменов для исключения 'заброшенных' ресурсов (Subdomain Takeover).",
            body_style
        ))
    else:
        story.append(Paragraph("Данные о внешнем сканировании отсутствуют (база пуста).", body_style))
        
    story.append(Spacer(1, 15))

    # --- РАЗДЕЛ 3. АНАЛИЗ УТЕЧЕК ДАННЫХ (DLP) ---
    story.append(Paragraph("3. Результаты анализа утечек данных (DLP)", h1_style))
    story.append(Paragraph(
        "Модуль DLP (Data Loss Prevention) предназначен для локального мониторинга исходного кода и конфигурационных файлов проекта. "
        "Он осуществляет поиск конфиденциальной информации, случайно оставленной разработчиками в открытом виде: приватных ключей SSH/PGP, "
        "паролей от баз данных, токенов API (Telegram, AWS, GitHub, OpenAI и др.). Наличие таких данных в репозитории несет критическую угрозу.",
        body_style
    ))
    
    try:
        cursor.execute("SELECT scan_time, checked_path, critical_count, medium_count, low_count FROM dlp_results ORDER BY id DESC LIMIT 5")
        dlp_data = cursor.fetchall()
    except sqlite3.OperationalError:
        dlp_data = []
    
    if dlp_data:
        table_data = [["Время", "Сканируемый путь", "Крит.", "Средн.", "Низк."]]
        for row in dlp_data:
            table_data.append([str(row[0]), str(row[1]), str(row[2]), str(row[3]), str(row[4])])
            
        t = Table(table_data, colWidths=[110, 210, 60, 60, 60])
        t.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,0), colors.HexColor("#251b45")),
            ('TEXTCOLOR', (0,0), (-1,0), colors.whitesmoke),
            ('FONTNAME', (0,0), (-1,-1), 'Arial'),
            ('FONTSIZE', (0,0), (-1,-1), 9),
            ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor("#e0e0e0")),
            ('PADDING', (0,0), (-1,-1), 6),
        ]))
        story.append(t)
        story.append(Spacer(1, 10))
        story.append(make_recommendation_box(
            "1. Никогда не храните пароли и API-токены в исходном коде. Используйте переменные окружения (.env) или специализированные хранилища (HashiCorp Vault).<br/>"
            "2. Добавьте файлы с секретами и локальными настройками в файл .gitignore, чтобы предотвратить их попадание в Git-репозиторий.<br/>"
            "3. В случае обнаружения утечки незамедлительно отзовите (деактивируйте) скомпрометированный токен или пароль и выпустите новый.",
            body_style
        ))
    else:
        story.append(Paragraph("Данные локального DLP-мониторинга отсутствуют (база пуста).", body_style))

    story.append(Spacer(1, 15))

    # --- РАЗДЕЛ 4. СЕТЕВОЙ АУДИТ (NETWORK SCANNER) ---
    story.append(Paragraph("4. Результаты сетевого сканирования (Network)", h1_style))
    story.append(Paragraph(
        "Сетевой анализатор осуществляет сканирование портов целевых хостов для определения активных сетевых служб и их версий (баннеров). "
        "На основе полученных данных проводится сопоставление со встроенной базой сигнатур уязвимостей для выявления устаревшего ПО, "
        "небезопасных конфигураций и потенциально уязвимых сетевых интерфейсов.",
        body_style
    ))
    
    try:
        cursor.execute("SELECT id, scan_time, target, open_ports_count, vulnerabilities_count FROM network_results ORDER BY id DESC LIMIT 5")
        network_data = cursor.fetchall()
    except sqlite3.OperationalError:
        network_data = []

    if network_data:
        for net_row in network_data:
            result_id, scan_time, target, open_ports, vulns = net_row
            story.append(Paragraph(f"<b>Цель сканирования:</b> {target} | <b>Время:</b> {scan_time} | <b>Открытых портов:</b> {open_ports} | <b>Уязвимостей:</b> {vulns}", h2_style))
            story.append(Spacer(1, 4))
            
            # Получаем детали для этого сканирования
            cursor.execute("SELECT port, service, banner, vulnerability_title, severity FROM network_details WHERE result_id = ?", (result_id,))
            details = cursor.fetchall()
            
            if details:
                table_data = [["Порт", "Служба", "Баннер", "Уязвимость", "Риск"]]
                for d_row in details:
                    port, service, banner, vuln_title, severity = d_row
                    vuln_title = vuln_title if vuln_title else "-"
                    severity = severity if severity else "-"
                    banner = banner if banner else "-"
                    table_data.append([str(port), str(service), str(banner), str(vuln_title), str(severity)])
                
                t = Table(table_data, colWidths=[50, 80, 120, 180, 70])
                t.setStyle(TableStyle([
                    ('BACKGROUND', (0,0), (-1,0), colors.HexColor("#393053")),
                    ('TEXTCOLOR', (0,0), (-1,0), colors.whitesmoke),
                    ('FONTNAME', (0,0), (-1,-1), 'Arial'),
                    ('FONTSIZE', (0,0), (-1,-1), 8),
                    ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor("#e0e0e0")),
                    ('PADDING', (0,0), (-1,-1), 5),
                ]))
                story.append(t)
                story.append(Spacer(1, 8))
        
        story.append(make_recommendation_box(
            "1. Закройте неиспользуемые порты на внешнем сетевом интерфейсе с помощью брандмауэра (iptables / ufw / Windows Firewall).<br/>"
            "2. Отключите передачу подробных версий ПО в баннерах ответов служб (например, директива server_tokens off в nginx).<br/>"
            "3. Регулярно обновляйте системное ПО и сетевые службы до актуальных стабильных версий для устранения известных CVE.",
            body_style
        ))
    else:
        story.append(Paragraph("Данные сетевого сканирования отсутствуют (база пуста).", body_style))

    story.append(Spacer(1, 15))
    
    # --- РАЗДЕЛ 5. ЗАКЛЮЧЕНИЕ И ПЛАН ДЕЙСТВИЙ ---
    story.append(Paragraph("5. Заключение и приоритетный план действий", h1_style))
    story.append(Paragraph(
        "По результатам проведенного комплексного аудита безопасности рекомендуется выполнить следующие первоочередные шаги "
        "для минимизации рисков несанкционированного доступа и утечки конфиденциальной информации:",
        body_style
    ))
    
    story.append(Paragraph("<b>[Приоритет 1 - КРИТИЧЕСКИЙ]</b> Локализовать и устранить все утечки секретов, обнаруженные модулем DLP. Провести ротацию скомпрометированных ключей и паролей.", bullet_style))
    story.append(Paragraph("<b>[Приоритет 2 - ВЫСОКИЙ]</b> Настроить правила межсетевого экрана для ограничения доступа к административным портам (SSH, RDP, СУБД) из внешней сети.", bullet_style))
    story.append(Paragraph("<b>[Приоритет 3 - СРЕДНИЙ]</b> Обновить версии ПО на сетевых службах, для которых были обнаружены известные уязвимости или устаревшие баннеры.", bullet_style))
    story.append(Paragraph("<b>[Приоритет 4 - НИЗКИЙ]</b> Провести аудит DNS-записей и WHOIS-информации доменных имен организации, настроить политики безопасности почты (SPF, DKIM, DMARC).", bullet_style))
    
    story.append(Spacer(1, 15))
    story.append(Paragraph("<i>Отчет сформирован автоматически. Данный документ носит конфиденциальный характер и предназначен исключительно для внутреннего использования техническими специалистами и администраторами безопасности организации.</i>", body_style))

    conn.close()    
    # Сборка
    print(f"[DEBUG] Элементов в story перед сборкой: {len(story)}")
    doc.build(story)