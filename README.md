# Периметр CLI

Терминальная версия комплекса «Периметр» — без GUI, все модули через подкоманды.

> ВНИМАНИЕ: исключительно для легального аудита. Сканирование сторонних ресурсов
> без согласия владельцев незаконно (ст. 272-274 УК РФ).

## Установка

```bash
cd perimeter-cli
pip install -e .
```

После этого команда `perimeter` доступна из любой директории.

## Команды

```bash
perimeter                        # баннер + справка
perimeter dlp C:\project --report   # DLP-скан папки (+ JSON/TXT отчёт в ./reports)
perimeter scan 192.168.1.1 --ports 22,80,8000-8100
perimeter osint example.com      # WHOIS + DNS + поддомены
perimeter web 10.0.0.5 --port 8080 --cookie session=abc
perimeter pipeline example.com   # OSINT -> скан всех найденных хостов
perimeter vault save github_token   # пароль и секрет вводятся скрыто
perimeter vault load github_token
perimeter vault list
perimeter report -o report.pdf   # PDF по истории сканов из БД
perimeter history --limit 10     # история сканов + имена найденных уязвимостей
perimeter clear --yes            # очистка истории
```

Результаты сканов автоматически пишутся в `perimeter.db` (в папке проекта),
vault хранится в `vault/` там же. Отчёты `--report` — в `./reports` текущей директории.

Полная справка по модулю: `perimeter <команда> -h` (описание, аргументы, примеры).
Примеры в справке — на любой ОС: пути можно писать как `~/project`, так и `C:\project`.

## Автодополнение (Tab)

```bash
# Linux / macOS / Git Bash / WSL — в ~/.bashrc
eval "$(perimeter completion bash)"

# zsh — в ~/.zshrc
eval "$(perimeter completion zsh)"
```

Tab по `perimeter <Tab>` предлагает команды, `perimeter vault <Tab>` — действия,
`perimeter web --<Tab>` — флаги модуля. Обычное дополнение файлов при этом
сохраняется (`perimeter dlp <Tab>` подставит путь).

PowerShell: работает на **7+** (во встроенной 5.1 нет `Register-ArgumentCompleter -Native`).

```powershell
# PowerShell 7+
perimeter completion powershell | Add-Content $PROFILE
```

На 5.1 либо обновиться (`winget install --id Microsoft.PowerShell`), либо включить
подсказки по истории ввода: `Set-PSReadLineOption -PredictionSource History`.

## Тест

```bash
python test_cli.py
```
