"""SQLite database connection and schema for Tech Monitoring."""

import os
import sqlite3
import threading

from techlog import get_logger

log = get_logger("db")

DB_FILE = os.environ.get("DB_FILE", "uptime.db")
DB_LOCK = threading.Lock()

SCHEMA = """
    CREATE TABLE IF NOT EXISTS services (
        id          INTEGER PRIMARY KEY AUTOINCREMENT,
        name        TEXT    NOT NULL,
        url         TEXT    NOT NULL UNIQUE,
        interval    INTEGER NOT NULL DEFAULT 60,
        retries     INTEGER NOT NULL DEFAULT 0,
        timeout     INTEGER NOT NULL DEFAULT 30,
        method      TEXT    NOT NULL DEFAULT 'GET',
        enabled     INTEGER NOT NULL DEFAULT 1,
        paused      INTEGER NOT NULL DEFAULT 0,
        created_at  TEXT    DEFAULT (datetime('now'))
    );
    CREATE TABLE IF NOT EXISTS checks (
        id          INTEGER PRIMARY KEY AUTOINCREMENT,
        service_id  INTEGER NOT NULL REFERENCES services(id) ON DELETE CASCADE,
        ts          REAL    NOT NULL,
        is_up       INTEGER NOT NULL,
        response_ms REAL    NOT NULL,
        status_code INTEGER
    );
    CREATE TABLE IF NOT EXISTS cert_info (
        service_id    INTEGER PRIMARY KEY REFERENCES services(id) ON DELETE CASCADE,
        ssl_expiry    TEXT,
        domain_expiry TEXT,
        updated_at    TEXT
    );
    CREATE TABLE IF NOT EXISTS users (
        id            INTEGER PRIMARY KEY AUTOINCREMENT,
        username      TEXT NOT NULL UNIQUE,
        password_hash TEXT NOT NULL,
        is_admin      INTEGER NOT NULL DEFAULT 0,
        created_at    TEXT DEFAULT (datetime('now'))
    );
    CREATE TABLE IF NOT EXISTS api_keys (
        id            INTEGER PRIMARY KEY AUTOINCREMENT,
        name          TEXT NOT NULL,
        key_hash      TEXT NOT NULL UNIQUE,
        key_prefix    TEXT NOT NULL,
        active        INTEGER NOT NULL DEFAULT 1,
        created_by    INTEGER REFERENCES users(id) ON DELETE SET NULL,
        created_at    TEXT DEFAULT (datetime('now')),
        last_used_at  TEXT
    );
    CREATE TABLE IF NOT EXISTS notification_channels (
        id         INTEGER PRIMARY KEY AUTOINCREMENT,
        name       TEXT NOT NULL,
        type       TEXT NOT NULL,
        config     TEXT NOT NULL,
        events     TEXT NOT NULL DEFAULT '["down","up"]',
        enabled    INTEGER NOT NULL DEFAULT 1,
        created_at TEXT DEFAULT (datetime('now'))
    );
    CREATE TABLE IF NOT EXISTS service_notifications (
        service_id  INTEGER NOT NULL REFERENCES services(id) ON DELETE CASCADE,
        channel_id  INTEGER NOT NULL REFERENCES notification_channels(id) ON DELETE CASCADE,
        PRIMARY KEY (service_id, channel_id)
    );
    CREATE INDEX IF NOT EXISTS idx_checks_svc ON checks(service_id, ts);
    CREATE INDEX IF NOT EXISTS idx_api_keys_hash ON api_keys(key_hash);
"""


def db():
    conn = sqlite3.connect(DB_FILE, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    with DB_LOCK:
        c = db()
        c.executescript(SCHEMA)
        c.commit()
        c.close()
    log.info("Database ready → %s", DB_FILE)
