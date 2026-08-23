AgentMonitor - Модуль резервного копирования

Цель

Добавить в AgentMonitor раздел:

💾 Бэкапы

* 📊 Backup Health
* 📦 Backup Report
* 🗄 DB Size
* 🧹 Cleanup

Модуль должен работать через существующий механизм WinRM и PostgreSQL.

⸻

1. Конфигурация серверов

Расширить config/servers.json.

Пример:

{
  "name": "SQL01",
  "host": "192.168.0.80",
  "backups": {
    "sql": [
      "R:\\Backups"
    ],
    "veeam": [
      "E:\\VeeamBackup"
    ],
    "1c": [
      "D:\\1C_Backups"
    ]
  },
  "dbsize": true
}

Описание:

* sql — каталоги SQL backup (*.bak, *.trn)
* veeam — каталоги Veeam backup
* 1c — каталоги выгрузок 1С (*.dt, *.zip)
* dbsize — включить получение размеров БД

⸻

2. Новые таблицы PostgreSQL

backup_metrics

CREATE TABLE backup_metrics (
    id SERIAL PRIMARY KEY,
    server_name VARCHAR(100),
    backup_type VARCHAR(20),
    backup_path TEXT,
    file_count INTEGER,
    oldest_file TIMESTAMP,
    newest_file TIMESTAMP,
    total_size_gb NUMERIC(12,2),
    disk_total_gb NUMERIC(12,2),
    disk_free_gb NUMERIC(12,2),
    created_at TIMESTAMP DEFAULT NOW()
);

⸻

database_sizes

CREATE TABLE database_sizes (
    id SERIAL PRIMARY KEY,
    server_name VARCHAR(100),
    database_name VARCHAR(255),
    size_gb NUMERIC(12,2),
    collected_at TIMESTAMP DEFAULT NOW()
);

⸻

3. Monitor

Создать новый модуль:

monitor/backup_collector.py

Запускать вместе с основным циклом мониторинга.

Период опроса:

каждые 5 минут.

⸻

4. Backup Collector

Для каждого пути backup:

Получить:

* количество файлов
* общий размер
* дату самого старого файла
* дату самого нового файла

Также получить параметры диска:

* общий объем
* свободное место
* процент заполнения

Сохранять данные в backup_metrics.

⸻

5. Раздел Telegram

Добавить новый пункт меню:

💾 Бэкапы

После нажатия:

📊 Backup Health
📦 Backup Report
🗄 DB Size
🧹 Cleanup

⸻

6. Backup Health

Сводный статус по всем серверам.

Пример:

💾 Backup Health

Всего серверов: 8

✅ Норма: 6
⚠️ Предупреждение: 1
🔴 Ошибка: 1

────────────

SQL01
✅ SQL Backup

1C01
✅ 1C Backup

EXCH01
⚠️ Последний backup старше 24 часов

FILE01
🔴 Backup каталог пуст

Правила:

Зеленый:

* есть файлы
* последний backup младше 24 часов

Желтый:

* последний backup старше 24 часов

Красный:

* каталог пуст
* каталог недоступен
* свободное место менее 10%

⸻

7. Backup Report

Выбор сервера.

Показывать:

* путь
* тип backup
* количество файлов
* размер
* самый старый backup
* самый новый backup
* фактический срок хранения
* размер диска
* свободное место

Пример:

💾 SQL01

Тип:
SQL

Путь:
R:\Backups

Файлов:
48

Самый старый:
01.06.2026

Самый новый:
26.06.2026

Хранение:
25 дней

Размер:
2.8 TB

Свободно:
1.2 TB

Заполнено:
70%

⸻

8. DB Size

Только для серверов где dbsize=true.

Через WinRM выполнить PowerShell:

Invoke-Sqlcmd

SQL запрос:

SELECT
    DB_NAME(database_id) AS dbname,
    CAST(SUM(size)*8/1024.0/1024 AS DECIMAL(18,2)) AS size_gb
FROM sys.master_files
GROUP BY database_id

Сохранять результат в database_sizes.

Отображение:

🗄 SQL01

new_pro_zko
49.7 GB

exchange
120.0 GB

reporting
8.1 GB

⸻

9. Cleanup

Только для SQL и 1С backup.

Veeam не удалять.

Поддерживаемые расширения:

* .bak
* .trn
* .dt
* .zip

⸻

Экран анализа

🧹 SQL01

Путь:
R:\Backups

Файлов:
138

Размер:
4.2 TB

Самый старый:
01.01.2026

Самый новый:
26.06.2026

Свободно:
8%

⸻

Действия

Кнопки:

Удалить 5 старейших
Удалить 10 старейших
Удалить 20 старейших

⸻

Предпросмотр

Показать список файлов.

Пример:

Будут удалены:

backup_20260101.bak
backup_20260102.bak
backup_20260103.bak

Всего:
10 файлов

Освободится:
842 GB

⸻

Подтверждение

Только после подтверждения пользователя.

Кнопки:

✅ Подтвердить
❌ Отмена

⸻

10. Backup Alerts

Добавить в существующий механизм алертов.

Примеры:

🚨 Backup Alert

SQL01

Последний backup:
3 дня назад

⸻

🚨 Backup Alert

FILE01

Свободно:
8%

Backup диск почти заполнен

⸻

11. Ограничения безопасности

Запрещено удаление:

* Veeam backup файлов
* любых файлов вне каталогов backup из servers.json

Все удаления должны логироваться.

⸻

Результат

После внедрения пользователь получает централизованный контроль:

* наличие резервных копий;
* возраст последнего backup;
* объем backup-хранилищ;
* заполнение дисков;
* размеры SQL баз;
* безопасную очистку старых backup файлов через Telegram.