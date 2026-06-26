"""Automatic weekly PDF report generation and email delivery."""

from __future__ import annotations

import datetime
import os
import threading
import time
from pathlib import Path
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from database import db, DB_LOCK
import notification
from report_pdf import fetch_service_report_stats, build_report_pdf
from report_settings import (
    get_weekly_settings,
    get_weekly_last_run_date,
    parse_recipient_emails,
    set_weekly_last_run_date,
)
from techlog import get_logger

log = get_logger("weekly")

_TEST_SEND_LOCK = threading.Lock()
_RECENT_TEST_SENDS: dict[str, float] = {}
_TEST_DEDUP_SECONDS = 90
_SCHEDULER_POLL_SECONDS = 30

DATA_DIR = Path(os.environ.get("DATA_DIR", "data"))
DEFAULT_PDF = DATA_DIR / "weekly_uptime.pdf"


def schedule_timezone_name() -> str:
    return get_weekly_settings().get("timezone") or "UTC"


def weekly_report_subject(end_date: datetime.date) -> str:
    return f"Weekly Monitoring Report ({end_date.year}-{end_date.month}-{end_date.day})"


def _load_email_channel(channel_id: int | None) -> dict:
    channel = notification.get_channel_by_id(channel_id)
    if not channel:
        raise ValueError("select an email notification channel in Settings → Reports")
    if channel["type"] != "email":
        raise ValueError("selected channel must be an email (SMTP) notification channel")
    if not channel.get("enabled", True):
        raise ValueError("selected email notification channel is disabled")
    cfg = channel["config"] or {}
    if not (cfg.get("smtp_host") or "").strip():
        raise ValueError("selected email channel is missing SMTP host — edit it under Notifications")
    return channel


def _report_timezone() -> ZoneInfo:
    try:
        return ZoneInfo(schedule_timezone_name())
    except ZoneInfoNotFoundError:
        log.warning("Unknown timezone %r — using UTC for weekly report schedule", schedule_timezone_name())
        return ZoneInfo("UTC")


def _schedule_now() -> datetime.datetime:
    return datetime.datetime.now(_report_timezone())


def generate_report_for_range(
    start_date: datetime.date,
    end_date: datetime.date,
    service_ids: list[int] | None = None,
    output_path: Path | None = None,
) -> tuple[Path, list[dict]]:
    start_dt = datetime.datetime.combine(start_date, datetime.time.min)
    end_dt = datetime.datetime.combine(end_date, datetime.time.max)
    from_ts = start_dt.timestamp()
    to_ts = end_dt.timestamp()

    if not service_ids:
        with DB_LOCK:
            c = db()
            rows = c.execute("SELECT id FROM services ORDER BY id").fetchall()
            c.close()
        service_ids = [int(r["id"]) for r in rows]

    stats_list = []
    for sid in service_ids:
        stats = fetch_service_report_stats(sid, from_ts, to_ts, db, DB_LOCK)
        if stats:
            stats_list.append(stats)

    if not stats_list:
        raise ValueError("no services with data for report")

    out = output_path or DEFAULT_PDF
    out.parent.mkdir(parents=True, exist_ok=True)
    build_report_pdf(stats_list, start_date, end_date, out)
    return out, stats_list


def generate_last_n_days_report(
    days: int = 7,
    service_ids: list[int] | None = None,
) -> tuple[Path, datetime.date, datetime.date, list[dict]]:
    end_date = datetime.date.today()
    start_date = end_date - datetime.timedelta(days=days)
    pdf_path, stats = generate_report_for_range(start_date, end_date, service_ids=service_ids)
    return pdf_path, start_date, end_date, stats


def _schedule_slot_key() -> str:
    s = get_weekly_settings()
    return "|".join([
        _schedule_now().date().isoformat(),
        str(s.get("weekday", 4)),
        str(s.get("hour", 9)),
        s.get("timezone") or "UTC",
    ])


def _already_ran_this_slot() -> bool:
    last = get_weekly_last_run_date()
    if not last:
        return False
    return last == _schedule_slot_key()


def _mark_ran_this_slot() -> None:
    set_weekly_last_run_date(_schedule_slot_key())


def run_weekly_report_job() -> None:
    s = get_weekly_settings()
    if not s["auto_enabled"]:
        return
    if not s["to_emails"]:
        raise ValueError("recipient emails are not configured in Settings → Reports")
    if not s.get("email_channel_id"):
        raise ValueError("email notification channel is not configured in Settings → Reports")

    send_weekly_report_email(
        s["to_emails"],
        s["days"],
        s["service_ids"],
        email_channel_id=s["email_channel_id"],
    )


def _test_send_key(to_emails: str | list[str], days: int, service_ids: list[int] | None) -> str:
    ids = sorted(int(x) for x in (service_ids or []))
    emails = ",".join(parse_recipient_emails(to_emails))
    return f"{emails}|{days}|{','.join(str(x) for x in ids)}"


def acquire_test_send_slot(to_emails: str | list[str], days: int, service_ids: list[int] | None) -> bool:
    """Return False if an identical test email was sent recently (duplicate request)."""
    key = _test_send_key(to_emails, days, service_ids)
    now = time.time()
    with _TEST_SEND_LOCK:
        last = _RECENT_TEST_SENDS.get(key)
        if last is not None and now - last < _TEST_DEDUP_SECONDS:
            return False
        _RECENT_TEST_SENDS[key] = now
        return True


def release_test_send_slot(to_emails: str | list[str], days: int, service_ids: list[int] | None) -> None:
    key = _test_send_key(to_emails, days, service_ids)
    with _TEST_SEND_LOCK:
        _RECENT_TEST_SENDS.pop(key, None)


def send_weekly_report_email(
    to_emails: str | list[str],
    days: int = 7,
    service_ids: list[int] | None = None,
    *,
    email_channel_id: int | None = None,
    test: bool = False,
) -> dict:
    recipients = parse_recipient_emails(to_emails)
    if not recipients:
        raise ValueError("recipient email is required")

    channel_id = email_channel_id or get_weekly_settings().get("email_channel_id")
    channel = _load_email_channel(channel_id)

    ids = service_ids or None
    pdf_path, start_date, end_date, stats = generate_last_n_days_report(days, service_ids=ids)
    subject = weekly_report_subject(end_date)
    if test:
        subject = f"[TEST] {subject}"
    notification.send_email_with_pdf(
        channel["config"],
        recipients,
        subject,
        str(pdf_path),
        env_fallback=False,
    )
    recipient_label = ", ".join(recipients)
    log.info(
        "Weekly report %semail sent to %s (%s services, %s to %s)",
        "test " if test else "",
        recipient_label, len(stats), start_date, end_date,
    )
    return {
        "to_emails": recipients,
        "services": len(stats),
        "start_date": str(start_date),
        "end_date": str(end_date),
        "pdf_path": str(pdf_path),
    }


def run_weekly_report_if_due() -> None:
    s = get_weekly_settings()
    if not s["auto_enabled"] or not s["to_emails"] or not s.get("email_channel_id"):
        return

    now = _schedule_now()
    if now.weekday() != s["weekday"] or now.hour < s["hour"]:
        return
    if _already_ran_this_slot():
        return

    weekdays = ("Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun")
    log.info(
        "Weekly report due — sending scheduled email (%s %02d:%02d %s)",
        weekdays[s["weekday"]] if 0 <= s["weekday"] <= 6 else "?",
        s["hour"],
        now.minute,
        s.get("timezone") or "UTC",
    )
    try:
        run_weekly_report_job()
        _mark_ran_this_slot()
    except Exception:
        log.exception("Scheduled weekly report failed")


def log_scheduler_status() -> None:
    s = get_weekly_settings()
    weekdays = ("Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun")
    tz = schedule_timezone_name()
    if s["auto_enabled"] and s["to_emails"] and s.get("email_channel_id"):
        log.info(
            "Weekly report scheduler active — %s at %02d:00 %s via channel #%s, last %s days → %s",
            weekdays[s["weekday"]] if 0 <= s["weekday"] <= 6 else "Fri",
            s["hour"],
            tz,
            s["email_channel_id"],
            s["days"],
            ", ".join(s["to_emails"]),
        )
    else:
        log.info(
            "Weekly report scheduler running (%s) — enable in Settings → Reports to send email",
            tz,
        )


_scheduler_started = False


def start_weekly_report_scheduler() -> None:
    global _scheduler_started
    if _scheduler_started:
        return
    _scheduler_started = True

    def _loop():
        while True:
            try:
                run_weekly_report_if_due()
            except Exception:
                log.exception("Weekly report scheduler check failed")
            time.sleep(_SCHEDULER_POLL_SECONDS)

    threading.Thread(target=_loop, daemon=True, name="weekly-report").start()
    log_scheduler_status()
