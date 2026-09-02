CREATE TABLE IF NOT EXISTS disk_metrics (
    id          SERIAL PRIMARY KEY,
    server_name TEXT NOT NULL,
    disk_name   TEXT NOT NULL,
    free_gb     NUMERIC(10,2) NOT NULL,
    used_gb     NUMERIC(10,2) NOT NULL,
    created_at  TIMESTAMP DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS server_status (
    id          SERIAL PRIMARY KEY,
    server_name TEXT NOT NULL,
    status      TEXT NOT NULL,
    error       TEXT,
    cpu_load    NUMERIC(5,2),
    ram_total   NUMERIC(10,2),
    ram_free    NUMERIC(10,2),
    uptime_seconds BIGINT,
    checked_at  TIMESTAMP DEFAULT NOW()
);

ALTER TABLE server_status
    ADD COLUMN IF NOT EXISTS cpu_load NUMERIC(5,2),
    ADD COLUMN IF NOT EXISTS ram_total NUMERIC(10,2),
    ADD COLUMN IF NOT EXISTS ram_free NUMERIC(10,2),
    ADD COLUMN IF NOT EXISTS uptime_seconds BIGINT;

CREATE TABLE IF NOT EXISTS service_status (
    id           SERIAL PRIMARY KEY,
    server_name  TEXT NOT NULL,
    service_name TEXT NOT NULL,
    display_name TEXT,
    status       TEXT NOT NULL,
    checked_at   TIMESTAMP DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS process_metrics (
    id           SERIAL PRIMARY KEY,
    server_name  TEXT NOT NULL,
    metric_type  TEXT NOT NULL,
    process_name TEXT NOT NULL,
    process_id   INTEGER,
    cpu_percent  NUMERIC(6,2),
    cpu_seconds  NUMERIC(12,2),
    memory_mb    NUMERIC(12,2),
    created_at   TIMESTAMP DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS backup_metrics (
    id             SERIAL PRIMARY KEY,
    server_name    TEXT NOT NULL,
    backup_type    TEXT NOT NULL,
    backup_path    TEXT NOT NULL,
    file_count     INTEGER,
    oldest_file    TIMESTAMP,
    newest_file    TIMESTAMP,
    newest_file_gb NUMERIC(12,3),
    total_size_gb  NUMERIC(12,2),
    disk_total_gb  NUMERIC(12,2),
    disk_free_gb   NUMERIC(12,2),
    status         TEXT NOT NULL DEFAULT 'ok',
    error          TEXT,
    created_at     TIMESTAMP DEFAULT NOW()
);

ALTER TABLE backup_metrics
    ADD COLUMN IF NOT EXISTS status TEXT NOT NULL DEFAULT 'ok',
    ADD COLUMN IF NOT EXISTS error TEXT,
    ADD COLUMN IF NOT EXISTS newest_file_gb NUMERIC(12,3);

CREATE TABLE IF NOT EXISTS database_sizes (
    id             SERIAL PRIMARY KEY,
    server_name    TEXT NOT NULL,
    database_name  TEXT NOT NULL,
    size_gb        NUMERIC(12,2),
    collected_at   TIMESTAMP DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS onec_log_metrics (
    id             SERIAL PRIMARY KEY,
    server_name    TEXT NOT NULL,
    log_name       TEXT NOT NULL,
    log_path       TEXT NOT NULL,
    total_size_gb  NUMERIC(12,2),
    file_count     INTEGER,
    oldest_file    TIMESTAMP,
    newest_file    TIMESTAMP,
    status         TEXT NOT NULL DEFAULT 'ok',
    error          TEXT,
    created_at     TIMESTAMP DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS backup_verifications (
    id             SERIAL PRIMARY KEY,
    server_name    TEXT NOT NULL,
    backup_path    TEXT NOT NULL,
    file_path      TEXT,
    file_size_gb   NUMERIC(12,2),
    file_modified  TIMESTAMP,
    status         TEXT NOT NULL,   -- ok | failed | no_bak | error
    error          TEXT,
    duration_sec   INTEGER,
    created_at     TIMESTAMP DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_backup_verifications_server_created
    ON backup_verifications (server_name, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_disk_server_created
    ON disk_metrics (server_name, disk_name, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_status_server_checked
    ON server_status (server_name, checked_at DESC);

CREATE INDEX IF NOT EXISTS idx_service_server_checked
    ON service_status (server_name, service_name, checked_at DESC);

CREATE INDEX IF NOT EXISTS idx_process_server_created
    ON process_metrics (server_name, metric_type, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_backup_server_type_path_created
    ON backup_metrics (server_name, backup_type, backup_path, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_database_sizes_server_db_collected
    ON database_sizes (server_name, database_name, collected_at DESC);

CREATE INDEX IF NOT EXISTS idx_onec_log_server_path_created
    ON onec_log_metrics (server_name, log_path, created_at DESC);

-- Индексы по времени: ежедневная очистка и выборки «за последний час»
-- фильтруют только по дате, а все индексы выше начинаются с server_name
-- и для этого не годятся — без них читалась вся таблица.
CREATE INDEX IF NOT EXISTS idx_disk_metrics_created
    ON disk_metrics (created_at DESC);

CREATE INDEX IF NOT EXISTS idx_server_status_checked
    ON server_status (checked_at DESC);

CREATE INDEX IF NOT EXISTS idx_service_status_checked
    ON service_status (checked_at DESC);

CREATE INDEX IF NOT EXISTS idx_process_metrics_created
    ON process_metrics (created_at DESC);

CREATE INDEX IF NOT EXISTS idx_backup_metrics_created
    ON backup_metrics (created_at DESC);

CREATE INDEX IF NOT EXISTS idx_database_sizes_collected
    ON database_sizes (collected_at DESC);

CREATE INDEX IF NOT EXISTS idx_onec_log_metrics_created
    ON onec_log_metrics (created_at DESC);

-- Аудит изменений конфигурации серверов из бота (кто/когда/что).
-- Не входит в автоочистку истории — записей мало, нужны для расследований.
CREATE TABLE IF NOT EXISTS config_audit (
    id          SERIAL PRIMARY KEY,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    user_id     BIGINT,
    username    TEXT,
    action      TEXT NOT NULL,   -- add | edit | toggle | services | delete | reboot
    target      TEXT,            -- имя сервера
    details     TEXT             -- что именно изменилось
);

CREATE INDEX IF NOT EXISTS idx_config_audit_created
    ON config_audit (created_at DESC);

-- Сводка журналов Windows и SQL для дашборда. Хранится СНИМКОМ: монитор
-- каждый раз читает журналы за последние сутки и заменяет записи сервера
-- целиком. Поэтому здесь нет ни дублей, ни роста со временем — и в
-- автоочистку истории эти таблицы не входят.
CREATE TABLE IF NOT EXISTS log_events (
    id           SERIAL PRIMARY KEY,
    server_name  TEXT NOT NULL,
    source       TEXT NOT NULL,      -- win | sql
    category     TEXT NOT NULL,      -- reboot|service|disk|app|logon | login|backup|engine|job
    level        TEXT NOT NULL,      -- crit | warn
    event_at     TEXT,               -- время по часам самого сервера, как его отдал журнал
    event_id     TEXT,               -- код события: 6008, 18456, …
    title        TEXT NOT NULL,
    detail       TEXT,
    event_count  INTEGER NOT NULL DEFAULT 1,   -- сколько одинаковых записей схлопнуто
    collected_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_log_events_server
    ON log_events (server_name, source);

-- Когда журналы читались в последний раз и чем это кончилось. Нужна, чтобы
-- отличить «в журналах чисто» от «до сервера не достучались»: снимок при
-- неудаче остаётся прошлый и обязан быть подписан как несвежий.
CREATE TABLE IF NOT EXISTS log_scans (
    server_name  TEXT NOT NULL,
    source       TEXT NOT NULL,
    collected_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    error        TEXT,
    PRIMARY KEY (server_name, source)
);

-- Сводка IIS. В отличие от журналов Windows здесь НАКОПЛЕНИЕ, а не снимок:
-- логи читаются по смещению, каждый проход приносит только новые строки,
-- и сутки складываются из этих кусков суммированием по ключу при чтении.
CREATE TABLE IF NOT EXISTS iis_events (
    id          SERIAL PRIMARY KEY,
    server_name TEXT NOT NULL,
    category    TEXT NOT NULL,   -- total|code|port|pub|scan|hit|login|ip|error|slowuri|hour|herr|herrd
    item        TEXT NOT NULL,   -- ключ внутри категории: '404.0', 'agro|192.0.2.30', …
    count       BIGINT NOT NULL DEFAULT 0,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_iis_events_created
    ON iis_events (created_at DESC);

CREATE INDEX IF NOT EXISTS idx_iis_events_server
    ON iis_events (server_name, category);

-- Докуда дочитан каждый файл. Потерять эти строки — значит либо перечитать
-- 20 ГБ истории, либо пропустить сутки.
CREATE TABLE IF NOT EXISTS iis_state (
    server_name TEXT NOT NULL,
    source      TEXT NOT NULL,   -- site | httperr
    file_name   TEXT NOT NULL,
    position    BIGINT NOT NULL,
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (server_name, source, file_name)
);

-- Публикации, пулы, объём каталога логов: меняются редко, хранятся снимком.
CREATE TABLE IF NOT EXISTS iis_facts (
    server_name TEXT NOT NULL,
    fact        TEXT NOT NULL,
    value       TEXT,
    error       TEXT,
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (server_name, fact)
);

-- Почтовая сводка Zimbra и Exchange (вкладка 📮 Почта в дашборде).
-- Снимок, а не история: сборщик каждый раз читает сутки целиком, и хранить
-- проходы незачем. Форма сводки общая для обеих почт — плитки, списки,
-- тревоги, — поэтому лежит одним JSON, а не разложена по колонкам: у
-- Zimbra и Exchange общих полей почти нет.
CREATE TABLE IF NOT EXISTS mail_snapshots (
    server_name  TEXT NOT NULL,
    kind         TEXT NOT NULL,      -- zimbra | exchange
    payload      TEXT,               -- {kpis: [...], groups: [...], alarms: [...]}
    error        TEXT,               -- чем кончился последний сбор
    collected_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (server_name, kind)
);

-- Заблокированные адреса (раздел 🛡 Блокировка IP). Источник истины —
-- здесь, а не на сервере: правило Windows Firewall не хранит ни срока, ни
-- причины, ни автора, а пересозданный сервер теряет список целиком.
-- Правило каждый раз собирается из этих строк.
CREATE TABLE IF NOT EXISTS fw_blocks (
    server_name TEXT NOT NULL,
    address     TEXT NOT NULL,   -- IP или подсеть: '192.0.2.10', '192.0.2.0/24'
    reason      TEXT,
    author      TEXT,            -- Telegram user_id того, кто заблокировал
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at  TIMESTAMPTZ,     -- NULL = бессрочно
    PRIMARY KEY (server_name, address)
);

-- Адреса, которые бот блокировать откажется: свой офис, узлы прокси.
CREATE TABLE IF NOT EXISTS fw_whitelist (
    server_name TEXT NOT NULL,
    address     TEXT NOT NULL,
    note        TEXT,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (server_name, address)
);

-- Кеш геоданных по IP. Адреса сотрудников меняются редко, а разделы почты
-- и IIS открывают помногу раз в день: без кеша каждый показ означал бы
-- обращение к внешнему сервису.
CREATE TABLE IF NOT EXISTS ip_geo (
    address      TEXT PRIMARY KEY,
    country      TEXT,
    country_code TEXT,            -- 'KZ' — из него собирается эмодзи флага
    city         TEXT,
    found        BOOLEAN NOT NULL DEFAULT FALSE,
    updated_at   TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Свои метки подсетей: точнее любой геобазы и работают там, где её нет
-- вовсе. У 10.10.3.87 географии не существует, а «🏢 Офис Астана» — есть.
CREATE TABLE IF NOT EXISTS ip_labels (
    network    TEXT PRIMARY KEY,  -- '10.10.3.0/24'
    label      TEXT NOT NULL,     -- '🏢 Офис Астана'
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
