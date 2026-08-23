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
