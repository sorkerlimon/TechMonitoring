"""Persisted weekly report schedule settings (database-backed)."""

from __future__ import annotations

import json
import re

from database import db, DB_LOCK

SETTINGS_KEY = "weekly_report"
_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")

DEFAULTS = {
    "auto_enabled": False,
    "to_emails": [],
    "weekday": 4,
    "hour": 9,
    "days": 7,
    "service_ids": [],
}


def parse_recipient_emails(value) -> list[str]:
    if value is None:
        return []
    if isinstance(value, list):
        parts = value
    else:
        text = str(value).replace(";", ",").replace("\n", ",")
        parts = text.split(",")
    seen: set[str] = set()
    out: list[str] = []
    for part in parts:
        email = (part or "").strip()
        if not email:
            continue
        key = email.lower()
        if key in seen:
            continue
        seen.add(key)
        out.append(email)
    return out


def resolve_recipient_emails(payload: dict | None, saved: dict | None = None) -> list[str]:
    payload = payload or {}
    saved = saved or {}
    for source in (payload.get("to_emails"), payload.get("to_email"),
                   saved.get("to_emails"), saved.get("to_email")):
        emails = parse_recipient_emails(source)
        if emails:
            return emails
    return []


def invalid_recipient_emails(emails: list[str]) -> list[str]:
    return [email for email in emails if not _EMAIL_RE.match(email)]


def _normalize(raw: dict | None) -> dict:
    data = {**DEFAULTS, **(raw or {})}
    data["auto_enabled"] = bool(data.get("auto_enabled"))
    emails = parse_recipient_emails(data.get("to_emails"))
    if not emails:
        emails = parse_recipient_emails(data.get("to_email"))
    data["to_emails"] = emails
    data.pop("to_email", None)
    try:
        data["weekday"] = int(data.get("weekday", 4))
    except (TypeError, ValueError):
        data["weekday"] = 4
    data["weekday"] = max(0, min(6, data["weekday"]))
    try:
        data["hour"] = int(data.get("hour", 9))
    except (TypeError, ValueError):
        data["hour"] = 9
    data["hour"] = max(0, min(23, data["hour"]))
    try:
        data["days"] = int(data.get("days", 7))
    except (TypeError, ValueError):
        data["days"] = 7
    data["days"] = max(1, min(90, data["days"]))
    ids = []
    for item in data.get("service_ids") or []:
        try:
            ids.append(int(item))
        except (TypeError, ValueError):
            continue
    data["service_ids"] = ids
    return data


def get_weekly_settings() -> dict:
    with DB_LOCK:
        c = db()
        row = c.execute(
            "SELECT value FROM app_settings WHERE key=?",
            (SETTINGS_KEY,),
        ).fetchone()
        c.close()
    if not row:
        return _normalize(None)
    try:
        return _normalize(json.loads(row["value"]))
    except (json.JSONDecodeError, TypeError):
        return _normalize(None)


def save_weekly_settings(payload: dict) -> dict:
    data = _normalize(payload)
    with DB_LOCK:
        c = db()
        c.execute(
            """INSERT INTO app_settings(key, value, updated_at)
               VALUES(?, ?, datetime('now'))
               ON CONFLICT(key) DO UPDATE SET
                 value=excluded.value,
                 updated_at=excluded.updated_at""",
            (SETTINGS_KEY, json.dumps(data)),
        )
        c.commit()
        c.close()
    return data


def report_config() -> tuple[bool, list[str], int, int, int, list[int]]:
    s = get_weekly_settings()
    return (
        s["auto_enabled"],
        s["to_emails"],
        s["hour"],
        s["weekday"],
        s["days"],
        s["service_ids"],
    )


def migrate_weekly_settings_from_env() -> None:
    """One-time import from .env when DB settings do not exist yet."""
    import os

    with DB_LOCK:
        c = db()
        row = c.execute(
            "SELECT 1 FROM app_settings WHERE key=?",
            (SETTINGS_KEY,),
        ).fetchone()
        c.close()
    if row:
        return

    to_email = (os.environ.get("WEEKLY_REPORT_TO") or os.environ.get("MAIL_REPORT_TO") or "").strip()
    enabled_raw = os.environ.get("WEEKLY_REPORT_ENABLED", "").strip().lower()
    if not to_email and enabled_raw not in ("1", "true", "yes"):
        return

    payload = {
        "auto_enabled": enabled_raw in ("1", "true", "yes") if enabled_raw else bool(to_email),
        "to_emails": parse_recipient_emails(to_email),
        "weekday": os.environ.get("WEEKLY_REPORT_WEEKDAY", "4"),
        "hour": os.environ.get("WEEKLY_REPORT_HOUR", "9"),
        "days": os.environ.get("WEEKLY_REPORT_DAYS", "7"),
        "service_ids": [],
    }
    save_weekly_settings(payload)
